package main

import (
	"context"
	"fmt"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/yuvalk/NetworkSecurityManager/pkg/client"
)

func contains(arr []netv1.PolicyType, str netv1.PolicyType) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func PortPrinter(port netv1.NetworkPolicyPort) {
	fmt.Println("Port", *port.Protocol, port.Port)
}

func IPBlockPrinter(ipblock netv1.IPBlock) {
	fmt.Println("CIDR", ipblock.CIDR)
	for _, except := range ipblock.Except {
		fmt.Println("Except", except)
	}
}

func LabelSelectorPrinter(selector metav1.LabelSelector) {
	for field, value := range selector.MatchLabels {
		fmt.Println("LabelSelector", field, value)
	}
}

func PeerPrinter(peer netv1.NetworkPolicyPeer) {
	fmt.Println("Peer", peer)
	if peer.PodSelector != nil {
		LabelSelectorPrinter(metav1.LabelSelector(*peer.PodSelector))
	}
	if peer.NamespaceSelector != nil {
		LabelSelectorPrinter(metav1.LabelSelector(*peer.NamespaceSelector))
	}
	if peer.IPBlock != nil {
		IPBlockPrinter(*peer.IPBlock)
	}
}

func PolicyPrinter(policy netv1.NetworkPolicy) {
	fmt.Println(policy.Name)
	if contains(policy.Spec.PolicyTypes, "Egress") {
		// fmt.Println(policy.Spec.Egress)
		for _, egress := range policy.Spec.Egress {
			// fmt.Println(egress.Ports)
			for _, port := range egress.Ports {
				PortPrinter(port)
			}
			for _, to := range egress.To {
				PeerPrinter(to)
			}
		}
	}
	if contains(policy.Spec.PolicyTypes, "Ingress") {
		fmt.Println("Ingress Policy")
		for _, ingress := range policy.Spec.Ingress {
			for _, port := range ingress.Ports {
				PortPrinter(port)
			}
			for _, from := range ingress.From {
				PeerPrinter(from)
			}
		}
	}
}

/*
#id(order)	From				to				action
	IpBlock	podSelector	namespaceSelector	ports	ipBlock	podSelector	namespaceSelector	ports
1	172.17.1.0/24			tcp/6379		role=db AND namespace=default			reject
2	172.17.0.0/16			tcp/6379		role=db AND namespace=default			allow
3		role=frontend AND namespace=default		tcp/6379		role=db AND namespace=default			allow
4			project=myproject	tcp/6379		role=db AND namespace=default			allow
5		role=db AND namespace=default			10.0.0.0/24			tcp/5978	allow
6	*	*	*	*	*	*	*	*	reject
*/

func IngressTranslator(ingress netv1.NetworkPolicyIngressRule, policy netv1.NetworkPolicy) {
	for _, from := range ingress.From {
		if from.IPBlock != nil {
			ipblock := *from.IPBlock
			for _, except := range ipblock.Except {
				fmt.Println("from:", except, "port:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: reject")
			}
			fmt.Println("from:", ipblock.CIDR, "port:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")
		}

		if from.PodSelector != nil {
			podselector := *from.PodSelector
			fmt.Println("from:", podselector, "ports:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")
		}

		if from.NamespaceSelector != nil {
			namespaceselector := *from.NamespaceSelector
			fmt.Println("from:", namespaceselector, "ports:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")
		}
	}
}

func PolicyRulesTranslator(policy netv1.NetworkPolicy) {
	if contains(policy.Spec.PolicyTypes, "Ingress") {
		for _, ingress := range policy.Spec.Ingress {
			IngressTranslator(ingress, policy)
		}
	}
}

func main() {
	test, err := client.Client.NetworkPolicies("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("err")
	}

	fmt.Printf("Network Policies: \n")
	if len(test.Items) == 0 {
		fmt.Printf("no policies\n")
	}

	for i, policy := range test.Items {
		fmt.Println(i, ":", policy.Name)
		//PolicyPrinter(policy)
		PolicyRulesTranslator(policy)

	}
}
