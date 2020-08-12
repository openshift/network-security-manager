package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/yuvalk/NetworkSecurityManager/pkg/client"
)

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
		fmt.Println(policy.Spec.PolicyTypes)

	}
}
