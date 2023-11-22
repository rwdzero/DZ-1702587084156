package k8s

import (
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotect"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotectdos"
	k8s_nginx_informers "github.com/nginxinc/kubernetes-ingress/pkg/client/informers/externalversions"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"sync"
)

type namespacedInformer struct {
	namespace                    string
	isSecretsEnabledNamespace    bool
	areCustomResourcesEnabled    bool
	appProtectEnabled            bool
	appProtectDosEnabled         bool
	stopCh                       chan struct{}
	sharedInformerFactory        informers.SharedInformerFactory
	secretInformerFactory        informers.SharedInformerFactory
	confSharedInformerFactory    k8s_nginx_informers.SharedInformerFactory
	dynInformerFactory           dynamicinformer.DynamicSharedInformerFactory
	ingressLister                storeToIngressLister
	endpointSliceLister          storeToEndpointSliceLister
	podLister                    indexerToPodLister
	svcLister                    cache.Store
	secretLister                 cache.Store
	virtualServerLister          cache.Store
	virtualServerRouteLister     cache.Store
	appProtectPolicyLister       cache.Store
	appProtectLogConfLister      cache.Store
	appProtectDosPolicyLister    cache.Store
	appProtectDosLogConfLister   cache.Store
	appProtectDosProtectedLister cache.Store
	appProtectUserSigLister      cache.Store
	transportServerLister        cache.Store
	policyLister                 cache.Store
	lock                         sync.RWMutex
	cacheSyncs                   []cache.InformerSynced
}

func (nsi *namespacedInformer) addAppProtectPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.PolicyGVR).Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectPolicyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addAppProtectLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.LogConfGVR).Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectLogConfLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addAppProtectUserSigHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.UserSigGVR).Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectUserSigLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addAppProtectDosPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotectdos.DosPolicyGVR).Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectDosPolicyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addAppProtectDosLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotectdos.DosLogConfGVR).Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectDosLogConfLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addAppProtectDosProtectedResourceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.Appprotectdos().V1beta1().DosProtectedResources().Informer()
	informer.AddEventHandler(handlers)
	nsi.appProtectDosProtectedLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addSecretHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.secretInformerFactory.Core().V1().Secrets().Informer()
	informer.AddEventHandler(handlers)
	nsi.secretLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addServiceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Core().V1().Services().Informer()
	informer.AddEventHandler(handlers)
	nsi.svcLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addIngressHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Networking().V1().Ingresses().Informer()
	informer.AddEventHandler(handlers)
	nsi.ingressLister = storeToIngressLister{Store: informer.GetStore()}

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addEndpointSliceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Discovery().V1().EndpointSlices().Informer()
	informer.AddEventHandler(handlers)
	var el storeToEndpointSliceLister
	el.Store = informer.GetStore()
	nsi.endpointSliceLister = el

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addPodHandler() {
	informer := nsi.sharedInformerFactory.Core().V1().Pods().Informer()
	nsi.podLister = indexerToPodLister{Indexer: informer.GetIndexer()}

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addVirtualServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().VirtualServers().Informer()
	informer.AddEventHandler(handlers)
	nsi.virtualServerLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addVirtualServerRouteHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().VirtualServerRoutes().Informer()
	informer.AddEventHandler(handlers)
	nsi.virtualServerRouteLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().Policies().Informer()
	informer.AddEventHandler(handlers)
	nsi.policyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addTransportServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().TransportServers().Informer()
	informer.AddEventHandler(handlers)
	nsi.transportServerLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) start() {
	go nsi.sharedInformerFactory.Start(nsi.stopCh)

	if nsi.isSecretsEnabledNamespace {
		go nsi.secretInformerFactory.Start(nsi.stopCh)
	}

	if nsi.areCustomResourcesEnabled {
		go nsi.confSharedInformerFactory.Start(nsi.stopCh)
	}

	if nsi.appProtectEnabled || nsi.appProtectDosEnabled {
		go nsi.dynInformerFactory.Start(nsi.stopCh)
	}
}

func (nsi *namespacedInformer) stop() {
	close(nsi.stopCh)
}
