package client

import (
	"os"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	networkv1client "k8s.io/client-go/kubernetes/typed/networking/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client defines the client set that will be used for testing
var Client *ClientsSet

func init() {
	Client = New("")
}

// ClientsSet provides the struct to talk with relevant API
type ClientsSet struct {
	client.Client
	corev1client.CoreV1Interface
	networkv1client.NetworkingV1Client
	appsv1client.AppsV1Interface
	Config *rest.Config
}

// New returns a *ClientBuilder with the given kubeconfig.
func New(kubeconfig string) *ClientsSet {
	var config *rest.Config
	var err error

	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	if kubeconfig != "" {
		glog.V(4).Infof("Loading kube client config from path %q", kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		glog.V(4).Infof("Using in-cluster kube client config")
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		glog.Infof("Failed to init kubernetes client, please check the $KUBECONFIG environment variable")
		return nil
	}

	myScheme := runtime.NewScheme()
	if err = scheme.AddToScheme(myScheme); err != nil {
		panic(err)
	}

	clientSet := &ClientsSet{}
	clientSet.CoreV1Interface = corev1client.NewForConfigOrDie(config)
	clientSet.AppsV1Interface = appsv1client.NewForConfigOrDie(config)
	clientSet.NetworkingV1Client = *networkv1client.NewForConfigOrDie(config)
	clientSet.Config = config

	clientSet.Client, err = client.New(config, client.Options{
		Scheme: myScheme,
	})

	if err != nil {
		return nil
	}

	return clientSet
}
