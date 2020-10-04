package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//	"k8s.io/apimachinery/pkg/labels"

	client "github.com/openshift/network-security-manager/pkg/client"

	"github.com/kataras/tablewriter"
	"github.com/landoop/tableprinter"
)

var counter int

var policies []FirewallPolicy
var firewallPolicy *FirewallPolicy

// check if arr contains str
func contains(arr []netv1.PolicyType, str netv1.PolicyType) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

// PortPrinter prints a formattted port definition
func PortPrinter(port netv1.NetworkPolicyPort) {
	fmt.Println("Port", *port.Protocol, port.Port)
}

// IPBlockPrinter prints a formatted IPBlock
func IPBlockPrinter(ipblock netv1.IPBlock) {
	fmt.Println("CIDR", ipblock.CIDR)
	for _, except := range ipblock.Except {
		fmt.Println("Except", except)
	}
}

// LabelSelectorPrinter prints a formatted labelselector
func LabelSelectorPrinter(selector metav1.LabelSelector) {
	for field, value := range selector.MatchLabels {
		fmt.Println("LabelSelector", field, value)
	}
}

// PeerPrinter prints a formatted networkpolicy peer
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

// PolicyPrinter prints a formatted networkpolicy
func PolicyPrinter(policy netv1.NetworkPolicy) {
	fmt.Println(policy.Name)
	if contains(policy.Spec.PolicyTypes, "Egress") {
		for _, egress := range policy.Spec.Egress {
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

// RulePrinter prints a formatted FirewallRule
func RulePrinter(rule FirewallRule) {
	json, err := json.Marshal(rule)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(json))
	fmt.Println(rule.Order, rule.From, rule.To, rule.Action)
}

// IngressTranslator translate ingress rule into FirewallRules
func IngressTranslator(ingress netv1.NetworkPolicyIngressRule, policy netv1.NetworkPolicy) {
	var ingressIPRejectRule FirewallRule

	for _, from := range ingress.From {
		if from.IPBlock != nil {
			ipblock := *from.IPBlock
			for _, except := range ipblock.Except {
				//fmt.Println(i, "from:", except, "port:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: reject")
				ingressIPRejectRule = FirewallRule{FirewallLocation{CIDR: except, Ports: ingress.Ports}, FirewallLocation{PodSelector: policy.Spec.PodSelector}, "REJECT", counter}
				firewallPolicy.Rules = append(firewallPolicy.Rules, ingressIPRejectRule)
				counter++
			}
			//fmt.Println(i, "from:", ipblock.CIDR, "port:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")
			ingressIPRejectRule = FirewallRule{FirewallLocation{CIDR: ipblock.CIDR, Ports: ingress.Ports}, FirewallLocation{PodSelector: policy.Spec.PodSelector}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, ingressIPRejectRule)
			counter++
		}

		if from.PodSelector != nil {
			podselector := *from.PodSelector
			//			fmt.Println(i, "from:", podselector, "ports:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")

			//			fmt.Println(i, "podselector:", podselector.String())

			ingressIPRejectRule = FirewallRule{FirewallLocation{PodSelector: podselector, Ports: ingress.Ports}, FirewallLocation{PodSelector: policy.Spec.PodSelector}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, ingressIPRejectRule)
			counter++
		}

		if from.NamespaceSelector != nil {
			namespaceselector := *from.NamespaceSelector
			//			fmt.Println(i, "from:", namespaceselector, "ports:", ingress.Ports, "to:", policy.Spec.PodSelector, "action: allow")
			ingressIPRejectRule = FirewallRule{FirewallLocation{NamespaceSelector: namespaceselector, Ports: ingress.Ports}, FirewallLocation{PodSelector: policy.Spec.PodSelector}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, ingressIPRejectRule)
			counter++
		}
	}
}

// EgressTranslator translate egress rule into FirewallRules
func EgressTranslator(egress netv1.NetworkPolicyEgressRule, policy netv1.NetworkPolicy) {
	var egressRule FirewallRule

	for _, to := range egress.To {
		if to.IPBlock != nil {
			ipblock := *to.IPBlock
			for _, except := range ipblock.Except {
				egressRule = FirewallRule{FirewallLocation{PodSelector: policy.Spec.PodSelector}, FirewallLocation{CIDR: except, Ports: egress.Ports}, "REJECT", counter}
				firewallPolicy.Rules = append(firewallPolicy.Rules, egressRule)
				counter++
			}
			egressRule = FirewallRule{FirewallLocation{PodSelector: policy.Spec.PodSelector}, FirewallLocation{CIDR: ipblock.CIDR, Ports: egress.Ports}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, egressRule)
			counter++
		}

		if to.PodSelector != nil {
			podselector := *to.PodSelector
			egressRule = FirewallRule{FirewallLocation{PodSelector: policy.Spec.PodSelector}, FirewallLocation{PodSelector: podselector, Ports: egress.Ports}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, egressRule)
			counter++
		}

		if to.NamespaceSelector != nil {
			namespaceselector := *to.NamespaceSelector
			egressRule = FirewallRule{FirewallLocation{PodSelector: policy.Spec.PodSelector}, FirewallLocation{NamespaceSelector: namespaceselector, Ports: egress.Ports}, "ALLOW", counter}
			firewallPolicy.Rules = append(firewallPolicy.Rules, egressRule)
			counter++
		}
	}
}

// PolicyRulesTranslator translate networkpolicy to FirewallPolicy with FirewallRules
func PolicyRulesTranslator(policy netv1.NetworkPolicy) {
	firewallPolicy = new(FirewallPolicy)
	firewallPolicy.Namespace = policy.ObjectMeta.Namespace
	firewallPolicy.Name = policy.Name

	counter = 0

	if contains(policy.Spec.PolicyTypes, "Ingress") {
		for _, ingress := range policy.Spec.Ingress {
			IngressTranslator(ingress, policy)
		}
	}
	if contains(policy.Spec.PolicyTypes, "Egress") {
		for _, egress := range policy.Spec.Egress {
			EgressTranslator(egress, policy)
		}
	}

	policies = append(policies, *firewallPolicy)

	printer := tableprinter.New(os.Stderr)

	// Optionally, customize the table, import of the underline 'tablewriter' package is required for that.
	printer.BorderTop, printer.BorderBottom, printer.BorderLeft, printer.BorderRight = true, true, true, true
	printer.CenterSeparator = "│"
	printer.ColumnSeparator = "│"
	printer.RowSeparator = "─"
	printer.HeaderBgColor = tablewriter.BgBlackColor
	printer.HeaderFgColor = tablewriter.FgGreenColor

	printer.Print(firewallPolicy.Rules)
}

func main() {
	test, err := client.Client.NetworkPolicies("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("err")
	}

	println("Network Policies:")
	if len(test.Items) == 0 {
		fmt.Printf("no policies\n")
	}

	for i, policy := range test.Items {
		println(i, ":", policy.Name)
		//PolicyPrinter(policy)
		PolicyRulesTranslator(policy)

	}

	json, err := json.Marshal(policies)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(json))
}
