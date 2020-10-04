package main

import (
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//FirewallPolicy define list of firewall rules coming from a single network policy
type FirewallPolicy struct {
	Name      string
	Namespace string
	Rules     []FirewallRule
}

//FirewallRule defines a single rule with from, to and action
type FirewallRule struct {
	From   FirewallLocation `header:"inline"`
	To     FirewallLocation `header:"To"`
	Action string           `header:"Action"`
	Order  int              `header:"Order"`
}

//FirewallLocation degines a location which can be either podselector, namespaceselector or CIDR
type FirewallLocation struct {
	PodSelector       metav1.LabelSelector      `json:"podSelector,omitempty" header:"PodSelector"`
	NamespaceSelector metav1.LabelSelector      `json:"namespaceSelector,omitempty" header:"NamespaceSelector"`
	CIDR              string                    `json:"CIDR,omitempty" header:"CIDR"`
	Ports             []netv1.NetworkPolicyPort `json:"ports,omitempty" header:"Ports"`
}
