package main

import (
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FirewallPolicy struct {
	Name      string
	Namespace string
	Rules     []FirewallRule
}

type FirewallRule struct {
	From   FirewallLocation `header:"inline"`
	To     FirewallLocation `header:"To"`
	Action string           `header:"Action"`
	Order  int              `header:"Order"`
}

type FirewallLocation struct {
	PodSelector       metav1.LabelSelector      `json:"podSelector,omitempty", header:"PodSelector"`
	NamespaceSelector metav1.LabelSelector      `json:"namespaceSelector,omitempty", header:"NamespaceSelector"`
	CIDR              string                    `json:"CIDR,omitempty", header:"CIDR"`
	Ports             []netv1.NetworkPolicyPort `json:"ports,omitempty", header:"Ports"`
}
