package k8s

import (
	"context"
	"fmt"
	"github.com/golang/glog"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotect"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotectdos"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/validation"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/dos/v1beta1"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	api_v1 "k8s.io/api/core/v1"
	discovery_v1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func syncSecret(task task, lbc *LoadBalancerController) {
	key := task.Key
	var obj interface{}
	var secrExists bool
	var err error

	namespace, name, err := ParseNamespaceName(key)
	if err != nil {
		glog.Warningf("Secret key %v is invalid: %v", key, err)
		return
	}
	obj, secrExists, err = lbc.getNamespacedInformer(namespace).secretLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	resources := lbc.configuration.FindResourcesForSecret(namespace, name)

	if lbc.areCustomResourcesEnabled {
		secretPols := lbc.getPoliciesForSecret(namespace, name)
		for _, pol := range secretPols {
			resources = append(resources, lbc.configuration.FindResourcesForPolicy(pol.Namespace, pol.Name)...)
		}

		resources = removeDuplicateResources(resources)
	}

	glog.V(2).Infof("Found %v Resources with Secret %v", len(resources), key)

	if !secrExists {
		lbc.secretStore.DeleteSecret(key)

		glog.V(2).Infof("Deleting Secret: %v\n", key)

		if len(resources) > 0 {
			lbc.handleRegularSecretDeletion(resources)
		}
		if lbc.isSpecialSecret(key) {
			glog.Warningf("A special TLS Secret %v was removed. Retaining the Secret.", key)
		}
		return
	}

	glog.V(2).Infof("Adding / Updating Secret: %v\n", key)

	secret := obj.(*api_v1.Secret)

	lbc.secretStore.AddOrUpdateSecret(secret)

	if lbc.isSpecialSecret(key) {
		lbc.handleSpecialSecretUpdate(secret)
		// we don't return here in case the special secret is also used in resources.
	}

	if len(resources) > 0 {
		lbc.handleSecretUpdate(secret, resources)
	}
}

func syncConfigMap(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing configmap %v", key)

	obj, configExists, err := lbc.configMapLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}
	if configExists {
		lbc.configMap = obj.(*api_v1.ConfigMap)
		externalStatusAddress, exists := lbc.configMap.Data["external-status-address"]
		if exists {
			lbc.statusUpdater.SaveStatusFromExternalStatus(externalStatusAddress)
		}
	} else {
		lbc.configMap = nil
	}

	if !lbc.isNginxReady {
		glog.V(3).Infof("Skipping ConfigMap update because the pod is not ready yet")
		return
	}

	if lbc.batchSyncEnabled {
		glog.V(3).Infof("Skipping ConfigMap update because batch sync is on")
		return
	}

	lbc.updateAllConfigs()
}

func syncService(task task, lbc *LoadBalancerController) {
	key := task.Key

	var obj interface{}
	var exists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, exists, err = lbc.getNamespacedInformer(ns).svcLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	// First case: the service is the external service for the Ingress Controller
	// In that case we need to update the statuses of all resources

	if lbc.IsExternalServiceKeyForStatus(key) {
		glog.V(3).Infof("Syncing service %v", key)

		if !exists {
			// service got removed
			lbc.statusUpdater.ClearStatusFromExternalService()
		} else {
			// service added or updated
			lbc.statusUpdater.SaveStatusFromExternalService(obj.(*api_v1.Service))
		}

		if lbc.reportStatusEnabled() {
			ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

			glog.V(3).Infof("Updating status for %v Ingresses", len(ingresses))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
			if err != nil {
				glog.Errorf("error updating ingress status in syncService: %v", err)
			}
		}

		if lbc.areCustomResourcesEnabled && lbc.reportCustomResourceStatusEnabled() {
			virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

			glog.V(3).Infof("Updating status for %v VirtualServers", len(virtualServers))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
			if err != nil {
				glog.V(3).Infof("error updating VirtualServer/VirtualServerRoute status in syncService: %v", err)
			}
		}

		// we don't return here because technically the same service could be used in the second case
	}

	// Second case: the service is referenced by some resources in the cluster

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForService(namespace, name)

	if len(resources) == 0 {
		return
	}
	glog.V(3).Infof("Syncing service %v", key)

	glog.V(3).Infof("Updating %v resources", len(resources))

	resourceExes := lbc.createExtendedResources(resources)

	warnings, updateErr := lbc.configurator.AddOrUpdateResources(resourceExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
}

func syncNamespace(task task, lbc *LoadBalancerController) {
	key := task.Key
	// process namespace and add to / remove from watched namespace list
	_, exists, err := lbc.namespaceLabeledLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !exists {
		// Check if change is because of a new label, or because of a deleted namespace
		ns, _ := lbc.client.CoreV1().Namespaces().Get(context.TODO(), key, meta_v1.GetOptions{})

		if ns != nil && ns.Status.Phase == api_v1.NamespaceActive {
			// namespace still exists
			glog.Infof("Removing Configuration for Unwatched Namespace: %v", key)
			// Watched label for namespace was removed
			// delete any now unwatched namespaced informer groups if required
			nsi := lbc.getNamespacedInformer(key)
			if nsi != nil {
				lbc.cleanupUnwatchedNamespacedResources(nsi)
				delete(lbc.namespacedInformers, key)
			}
		} else {
			glog.Infof("Deleting Watchers for Deleted Namespace: %v", key)
			nsi := lbc.getNamespacedInformer(key)
			if nsi != nil {
				lbc.removeNamespacedInformer(nsi, key)
			}
		}
		if lbc.certManagerController != nil {
			lbc.certManagerController.RemoveNamespacedInformer(key)
		}
		if lbc.externalDNSController != nil {
			lbc.externalDNSController.RemoveNamespacedInformer(key)
		}
	} else {
		// check if informer group already exists
		// if not create new namespaced informer group
		// update cert-manager informer group if required
		// update external-dns informer group if required
		glog.V(3).Infof("Adding or Updating Watched Namespace: %v", key)
		nsi := lbc.getNamespacedInformer(key)
		if nsi == nil {
			glog.Infof("Adding New Watched Namespace: %v", key)
			nsi = lbc.newNamespacedInformer(key)
			nsi.start()
		}
		if lbc.certManagerController != nil {
			lbc.certManagerController.AddNewNamespacedInformer(key)
		}
		if lbc.externalDNSController != nil {
			lbc.externalDNSController.AddNewNamespacedInformer(key)
		}
		if !cache.WaitForCacheSync(nsi.stopCh, nsi.cacheSyncs...) {
			return
		}
	}
}

func syncVirtualServerRoute(task task, lbc *LoadBalancerController) {
	key := task.Key
	var obj interface{}
	var exists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, exists, err = lbc.getNamespacedInformer(ns).virtualServerRouteLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !exists {
		glog.V(2).Infof("Deleting VirtualServerRoute: %v\n", key)

		changes, problems = lbc.configuration.DeleteVirtualServerRoute(key)
	} else {
		glog.V(2).Infof("Adding or Updating VirtualServerRoute: %v\n", key)

		vsr := obj.(*conf_v1.VirtualServerRoute)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func syncIngress(task task, lbc *LoadBalancerController) {
	key := task.Key
	var ing *networking.Ingress
	var ingExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	ing, ingExists, err = lbc.getNamespacedInformer(ns).ingressLister.GetByKeySafe(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !ingExists {
		glog.V(2).Infof("Deleting Ingress: %v\n", key)

		changes, problems = lbc.configuration.DeleteIngress(key)
	} else {
		glog.V(2).Infof("Adding or Updating Ingress: %v\n", key)

		changes, problems = lbc.configuration.AddOrUpdateIngress(ing)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func syncEndpointSlices(task task, lbc *LoadBalancerController) bool {
	key := task.Key
	var obj interface{}
	var endpointSliceExists bool
	var err error
	var resourcesFound bool

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, endpointSliceExists, err = lbc.getNamespacedInformer(ns).endpointSliceLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return false
	}

	if !endpointSliceExists {
		return false
	}

	endpointSlice := obj.(*discovery_v1.EndpointSlice)
	svcResource := lbc.configuration.FindResourcesForService(endpointSlice.Namespace, endpointSlice.Labels["kubernetes.io/service-name"])

	resourceExes := lbc.createExtendedResources(svcResource)

	if len(resourceExes.IngressExes) > 0 {
		resourcesFound = true
		glog.V(3).Infof("Updating EndpointSlices for %v", resourceExes.IngressExes)
		err = lbc.configurator.UpdateEndpoints(resourceExes.IngressExes)
		if err != nil {
			glog.Errorf("Error updating EndpointSlices for %v: %v", resourceExes.IngressExes, err)
		}
	}

	if len(resourceExes.MergeableIngresses) > 0 {
		resourcesFound = true
		glog.V(3).Infof("Updating EndpointSlices for %v", resourceExes.MergeableIngresses)
		err = lbc.configurator.UpdateEndpointsMergeableIngress(resourceExes.MergeableIngresses)
		if err != nil {
			glog.Errorf("Error updating EndpointSlices for %v: %v", resourceExes.MergeableIngresses, err)
		}
	}

	if lbc.areCustomResourcesEnabled {
		if len(resourceExes.VirtualServerExes) > 0 {
			resourcesFound = true
			glog.V(3).Infof("Updating EndpointSlices for %v", resourceExes.VirtualServerExes)
			err := lbc.configurator.UpdateEndpointsForVirtualServers(resourceExes.VirtualServerExes)
			if err != nil {
				glog.Errorf("Error updating EndpointSlices for %v: %v", resourceExes.VirtualServerExes, err)
			}
		}

		if len(resourceExes.TransportServerExes) > 0 {
			resourcesFound = true
			glog.V(3).Infof("Updating EndpointSlices for %v", resourceExes.TransportServerExes)
			err := lbc.configurator.UpdateEndpointsForTransportServers(resourceExes.TransportServerExes)
			if err != nil {
				glog.Errorf("Error updating EndpointSlices for %v: %v", resourceExes.TransportServerExes, err)
			}
		}
	}
	return resourcesFound
}

func syncIngressLink(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(2).Infof("Adding, Updating or Deleting IngressLink: %v", key)

	obj, exists, err := lbc.ingressLinkLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !exists {
		// IngressLink got removed
		lbc.statusUpdater.ClearStatusFromIngressLink()
	} else {
		// IngressLink is added or updated
		link := obj.(*unstructured.Unstructured)

		// spec.virtualServerAddress contains the IP of the BIG-IP device
		ip, found, err := unstructured.NestedString(link.Object, "spec", "virtualServerAddress")
		if err != nil {
			glog.Errorf("Failed to get virtualServerAddress from IngressLink %s: %v", key, err)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else if !found {
			glog.Errorf("virtualServerAddress is not found in IngressLink %s", key)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else if ip == "" {
			glog.Warningf("IngressLink %s has the empty virtualServerAddress field", key)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else {
			lbc.statusUpdater.SaveStatusFromIngressLink(ip)
		}
	}

	if lbc.reportStatusEnabled() {
		ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

		glog.V(3).Infof("Updating status for %v Ingresses", len(ingresses))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
		if err != nil {
			glog.Errorf("Error updating ingress status in syncIngressLink: %v", err)
		}
	}

	if lbc.areCustomResourcesEnabled && lbc.reportCustomResourceStatusEnabled() {
		virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

		glog.V(3).Infof("Updating status for %v VirtualServers", len(virtualServers))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
		if err != nil {
			glog.V(3).Infof("Error updating VirtualServer/VirtualServerRoute status in syncIngressLink: %v", err)
		}
	}
}

func syncPolicy(task task, lbc *LoadBalancerController) {
	key := task.Key
	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).policyLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	glog.V(2).Infof("Adding, Updating or Deleting Policy: %v\n", key)

	if polExists && lbc.HasCorrectIngressClass(obj) {
		pol := obj.(*conf_v1.Policy)
		err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enableOIDC, lbc.appProtectEnabled)
		if err != nil {
			msg := fmt.Sprintf("Policy %v/%v is invalid and was rejected: %v", pol.Namespace, pol.Name, err)
			lbc.recorder.Eventf(pol, api_v1.EventTypeWarning, "Rejected", msg)

			if lbc.reportCustomResourceStatusEnabled() {
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateInvalid, "Rejected", msg)
				if err != nil {
					glog.V(3).Infof("Failed to update policy %s status: %v", key, err)
				}
			}
		} else {
			msg := fmt.Sprintf("Policy %v/%v was added or updated", pol.Namespace, pol.Name)
			lbc.recorder.Eventf(pol, api_v1.EventTypeNormal, "AddedOrUpdated", msg)

			if lbc.reportCustomResourceStatusEnabled() {
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateValid, "AddedOrUpdated", msg)
				if err != nil {
					glog.V(3).Infof("Failed to update policy %s status: %v", key, err)
				}
			}
		}
	}

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForPolicy(namespace, name)
	resourceExes := lbc.createExtendedResources(resources)

	// Only VirtualServers support policies
	if len(resourceExes.VirtualServerExes) == 0 {
		return
	}

	warnings, updateErr := lbc.configurator.AddOrUpdateVirtualServers(resourceExes.VirtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)

	// Note: updating the status of a policy based on a reload is not needed.
}

func syncTransportServer(task task, lbc *LoadBalancerController) {
	key := task.Key
	var obj interface{}
	var tsExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, tsExists, err = lbc.getNamespacedInformer(ns).transportServerLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !tsExists {
		glog.V(2).Infof("Deleting TransportServer: %v\n", key)
		changes, problems = lbc.configuration.DeleteTransportServer(key)
	} else {
		glog.V(2).Infof("Adding or Updating TransportServer: %v\n", key)
		ts := obj.(*conf_v1.TransportServer)
		changes, problems = lbc.configuration.AddOrUpdateTransportServer(ts)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func syncGlobalConfiguration(task task, lbc *LoadBalancerController) {
	key := task.Key
	obj, gcExists, err := lbc.globalConfigurationLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem
	var validationErr error

	if !gcExists {
		glog.V(2).Infof("Deleting GlobalConfiguration: %v\n", key)

		changes, problems = lbc.configuration.DeleteGlobalConfiguration()
	} else {
		glog.V(2).Infof("Adding or Updating GlobalConfiguration: %v\n", key)

		gc := obj.(*conf_v1.GlobalConfiguration)
		changes, problems, validationErr = lbc.configuration.AddOrUpdateGlobalConfiguration(gc)
	}

	updateErr := lbc.processChangesFromGlobalConfiguration(changes)

	if gcExists {
		eventTitle := "Updated"
		eventType := api_v1.EventTypeNormal
		eventMessage := fmt.Sprintf("GlobalConfiguration %s was added or updated", key)

		if validationErr != nil {
			eventTitle = "Rejected"
			eventType = api_v1.EventTypeWarning
			eventMessage = fmt.Sprintf("GlobalConfiguration %s is invalid and was rejected: %v", key, validationErr)
		}

		if updateErr != nil {
			eventTitle += "WithError"
			eventType = api_v1.EventTypeWarning
			eventMessage = fmt.Sprintf("%s; with reload error: %v", eventMessage, updateErr)
		}

		gc := obj.(*conf_v1.GlobalConfiguration)
		lbc.recorder.Eventf(gc, eventType, eventTitle, eventMessage)
	}

	lbc.processProblems(problems)
}

func syncVirtualServer(task task, lbc *LoadBalancerController) {
	key := task.Key
	var obj interface{}
	var vsExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, vsExists, err = lbc.getNamespacedInformer(ns).virtualServerLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !vsExists {
		glog.V(2).Infof("Deleting VirtualServer: %v\n", key)

		changes, problems = lbc.configuration.DeleteVirtualServer(key)
	} else {
		glog.V(2).Infof("Adding or Updating VirtualServer: %v\n", key)

		vs := obj.(*conf_v1.VirtualServer)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServer(vs)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func syncSVIDRotation(svidResponse *workloadapi.X509Context, lbc *LoadBalancerController) {
	lbc.syncLock.Lock()
	defer lbc.syncLock.Unlock()
	glog.V(3).Info("Rotating SPIFFE Certificates")
	err := lbc.configurator.AddOrUpdateSpiffeCerts(svidResponse)
	if err != nil {
		glog.Errorf("failed to rotate SPIFFE certificates: %v", err)
	}
}

func syncAppProtectPolicy(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectPolicy %v", key)

	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).appProtectPolicyLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotect.Change
	var problems []appprotect.Problem

	if !polExists {
		glog.V(2).Infof("Deleting AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeletePolicy(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdatePolicy(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)
}

func syncAppProtectLogConf(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectLogConf %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectLogConfLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotect.Change
	var problems []appprotect.Problem

	if !confExists {
		glog.V(2).Infof("Deleting AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeleteLogConf(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdateLogConf(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)
}

func syncAppProtectUserSig(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectUserSig %v", key)
	var obj interface{}
	var sigExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, sigExists, err = lbc.getNamespacedInformer(ns).appProtectUserSigLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var change appprotect.UserSigChange
	var problems []appprotect.Problem

	if !sigExists {
		glog.V(2).Infof("Deleting AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.DeleteUserSig(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.AddOrUpdateUserSig(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectUserSigChange(change)
	lbc.processAppProtectProblems(problems)
}

func syncAppProtectDosPolicy(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectDosPolicy %v", key)
	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).appProtectDosPolicyLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if !polExists {
		glog.V(2).Infof("Deleting APDosPolicy: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeletePolicy(key)
	} else {
		glog.V(2).Infof("Adding or Updating APDosPolicy: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdatePolicy(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}

func syncAppProtectDosLogConf(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing APDosLogConf %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectDosLogConfLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if !confExists {
		glog.V(2).Infof("Deleting APDosLogConf: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeleteLogConf(key)
	} else {
		glog.V(2).Infof("Adding or Updating APDosLogConf: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdateLogConf(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}

func syncDosProtectedResource(task task, lbc *LoadBalancerController) {
	key := task.Key
	glog.V(3).Infof("Syncing DosProtectedResource %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectDosProtectedLister.GetByKey(key)

	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if confExists {
		glog.V(2).Infof("Adding or Updating DosProtectedResource: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdateDosProtectedResource(obj.(*v1beta1.DosProtectedResource))
	} else {
		glog.V(2).Infof("Deleting DosProtectedResource: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeleteProtectedResource(key)
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}
