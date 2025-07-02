/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"context"
	"fmt"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/containers"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/secrets"
	"k8s.io/cloud-provider-openstack/pkg/metrics"
	cpoerrors "k8s.io/cloud-provider-openstack/pkg/util/errors"
)

const (
	// BarbicanSecretContainerCertKey is the name for the key that references the certificate
	// It will also be the suffix for the Barbican Secret that holds the actual certificate
	BarbicanSecretContainerCertKey = "certificate"

	// BarbicanSecretContainerPrivateKeyKey is the name for the key that references the private key
	// It will also be the suffix for the Barbican Secret that holds the actual private key
	BarbicanSecretContainerPrivateKeyKey = "private_key"

	// BarbicanSecretContainerIntermediatesKey is the name for the key that references the intermediates
	// It will also be the suffix for the Barbican Secret that holds the actual intermediates
	BarbicanSecretContainerIntermediatesKey = "intermediates"

	// BarbicanSecretContainerPrivateKeyPassphraseKey is the name for the key that references the private key passphrase
	// It will also be the suffix for the Barbican Secret that holds the actual private key passphrase
	BarbicanSecretContainerPrivateKeyPassphraseKey = "private_key_passphrase"
)

type CertificateChain struct {
	Certificate          Certificate
	PrivateKey           *Certificate
	Intermediates        *Certificate
	PrivateKeyPassphrase *string
}

type Certificate struct {
	PayloadContentType string
	Payload            string
}

// EnsureSecret creates a secret if it doesn't exist.
func EnsureSecret(ctx context.Context, client *gophercloud.ServiceClient, name string, payloadType string, payload string, secretType secrets.SecretType) (string, error) {
	secret, err := GetSecret(ctx, client, name)
	if err != nil {
		if err == cpoerrors.ErrNotFound {
			// Create a new one
			return CreateSecret(ctx, client, name, payloadType, payload, secretType)
		}

		return "", err
	}

	return secret.SecretRef, nil
}

// EnsureSecret creates a secret if it doesn't exist.
func EnsureCertificateSecret(ctx context.Context, client *gophercloud.ServiceClient, name string, certificate Certificate) (string, error) {
	return EnsureSecret(ctx, client, name, certificate.PayloadContentType, certificate.Payload, secrets.CertificateSecret)
}

// GetSecret returns the secret by name
func GetSecret(ctx context.Context, client *gophercloud.ServiceClient, name string) (*secrets.Secret, error) {
	listOpts := secrets.ListOpts{
		Name:       name,
		SecretType: secrets.OpaqueSecret,
	}
	mc := metrics.NewMetricContext("secret", "list")
	allPages, err := secrets.List(client, listOpts).AllPages(ctx)
	if mc.ObserveRequest(err) != nil {
		return nil, err
	}
	allSecrets, err := secrets.ExtractSecrets(allPages)
	if err != nil {
		return nil, err
	}

	if len(allSecrets) == 0 {
		return nil, cpoerrors.ErrNotFound
	}
	if len(allSecrets) > 1 {
		return nil, cpoerrors.ErrMultipleResults
	}

	return &allSecrets[0], nil
}

// CreateSecret creates a secret in Barbican, returns the secret url.
func CreateSecret(ctx context.Context, client *gophercloud.ServiceClient, name string, payloadContentType string, payload string, secretType secrets.SecretType) (string, error) {
	createOpts := secrets.CreateOpts{
		Name:                   name,
		Algorithm:              "aes",
		Mode:                   "cbc",
		BitLength:              256,
		PayloadContentType:     payloadContentType,
		PayloadContentEncoding: "base64",
		Payload:                payload,
		SecretType:             secretType,
	}
	mc := metrics.NewMetricContext("secret", "create")
	secret, err := secrets.Create(ctx, client, createOpts).Extract()
	if mc.ObserveRequest(err) != nil {
		return "", err
	}
	return secret.SecretRef, nil
}

// CreateCertificateSecret creates a secret in Barbican, returns the secret url.
func CreateCertificateSecret(ctx context.Context, client *gophercloud.ServiceClient, name string, payloadContentType string, payload string) (string, error) {
	createOpts := secrets.CreateOpts{
		Name:                   name,
		Algorithm:              "aes",
		Mode:                   "cbc",
		BitLength:              256,
		PayloadContentType:     payloadContentType,
		PayloadContentEncoding: "base64",
		Payload:                payload,
		SecretType:             secrets.CertificateSecret,
	}
	mc := metrics.NewMetricContext("secret", "create")
	secret, err := secrets.Create(ctx, client, createOpts).Extract()
	if mc.ObserveRequest(err) != nil {
		return "", err
	}
	return secret.SecretRef, nil
}

// ParseSecretID return secret ID from secretRef
func ParseSecretID(ref string) (string, error) {
	parts := strings.Split(ref, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("could not parse %s", ref)
	}

	return parts[len(parts)-1], nil
}

// DeleteSecrets deletes all the secrets that including the name string.
func DeleteSecrets(ctx context.Context, client *gophercloud.ServiceClient, partName string) error {
	listOpts := secrets.ListOpts{
		SecretType: secrets.OpaqueSecret,
	}
	mc := metrics.NewMetricContext("secret", "list")
	allPages, err := secrets.List(client, listOpts).AllPages(ctx)
	if mc.ObserveRequest(err) != nil {
		return err
	}
	allSecrets, err := secrets.ExtractSecrets(allPages)
	if err != nil {
		return err
	}

	for _, s := range allSecrets {
		if strings.Contains(s.Name, partName) {
			secretID, err := ParseSecretID(s.SecretRef)
			if err != nil {
				return err
			}
			mc := metrics.NewMetricContext("secret", "delete")
			err = secrets.Delete(ctx, client, secretID).ExtractErr()
			if mc.ObserveRequest(err) != nil && !cpoerrors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

// EnsureContainer creates a container with the secret if it doesn't exist.
func EnsureContainer(ctx context.Context, client *gophercloud.ServiceClient, name string, certificateChain CertificateChain) (string, error) {

	container, err := GetContainer(ctx, client, name)
	if err != nil {
		if err == cpoerrors.ErrNotFound {
			var secretRefs []containers.SecretRef
			// Create the different certificates as secrets if needed
			secretRef, err := EnsureCertificateSecret(ctx, client, name+"_"+BarbicanSecretContainerCertKey, certificateChain.Certificate)
			if err != nil {
				return "", err
			}
			secretRefs = append(secretRefs, containers.SecretRef{SecretRef: secretRef, Name: BarbicanSecretContainerCertKey})

			if certificateChain.PrivateKey != nil {
				secretRef, err := EnsureCertificateSecret(ctx, client, name+"_"+BarbicanSecretContainerPrivateKeyKey, *certificateChain.PrivateKey)
				if err != nil {
					return "", err
				}
				secretRefs = append(secretRefs, containers.SecretRef{SecretRef: secretRef, Name: BarbicanSecretContainerPrivateKeyKey})
			}

			if certificateChain.PrivateKeyPassphrase != nil {
				secretRef, err := EnsureSecret(ctx, client, name+"_"+BarbicanSecretContainerPrivateKeyPassphraseKey,
					certificateChain.PrivateKey.PayloadContentType, certificateChain.PrivateKey.Payload, secrets.PassphraseSecret)
				if err != nil {
					return "", err
				}
				secretRefs = append(secretRefs, containers.SecretRef{SecretRef: secretRef, Name: BarbicanSecretContainerPrivateKeyPassphraseKey})
			}

			if certificateChain.Intermediates != nil {
				secretRef, err := EnsureCertificateSecret(ctx, client, name+"_"+BarbicanSecretContainerIntermediatesKey, *certificateChain.Intermediates)
				if err != nil {
					return "", err
				}
				secretRefs = append(secretRefs, containers.SecretRef{SecretRef: secretRef, Name: BarbicanSecretContainerIntermediatesKey})
			}

			container, err := CreateContainer(ctx, client, name, secretRefs)
			return container, err
		}

		return "", err
	}

	return container.ContainerRef, nil
}

// GetContainer returns the container by name
func GetContainer(ctx context.Context, client *gophercloud.ServiceClient, name string) (*containers.Container, error) {
	listOpts := containers.ListOpts{
		Name: name,
	}
	mc := metrics.NewMetricContext("container", "list")
	allPages, err := containers.List(client, listOpts).AllPages(ctx)
	if mc.ObserveRequest(err) != nil {
		return nil, err
	}
	allContainers, err := containers.ExtractContainers(allPages)
	if err != nil {
		return nil, err
	}

	if len(allContainers) == 0 {
		return nil, cpoerrors.ErrNotFound
	}
	if len(allContainers) > 1 {
		return nil, cpoerrors.ErrMultipleResults
	}

	return &allContainers[0], nil
}

// CreateContainer creates a secret in Barbican, returns the secret url.
func CreateContainer(ctx context.Context, client *gophercloud.ServiceClient, name string, secretRefs []containers.SecretRef) (string, error) {
	createOpts := containers.CreateOpts{Name: name, Type: containers.CertificateContainer, SecretRefs: secretRefs}
	mc := metrics.NewMetricContext("container", "create")
	container, err := containers.Create(ctx, client, createOpts).Extract()
	if mc.ObserveRequest(err) != nil {
		return "", err
	}
	return container.ContainerRef, nil
}

// DeleteContainers deletes all the containers that including the name string.
// TODO: Deletet linked secrets
func DeleteContainers(ctx context.Context, client *gophercloud.ServiceClient, partName string) error {
	listOpts := containers.ListOpts{Name: partName}
	mc := metrics.NewMetricContext("container", "list")
	allPages, err := containers.List(client, listOpts).AllPages(ctx)
	if mc.ObserveRequest(err) != nil {
		return err
	}
	allContainers, err := containers.ExtractContainers(allPages)
	if err != nil {
		return err
	}

	for _, c := range allContainers {
		if strings.Contains(c.Name, partName) {
			containerID, err := ParseSecretID(c.ContainerRef)
			if err != nil {
				return err
			}
			mc := metrics.NewMetricContext("container", "delete")
			err = containers.Delete(ctx, client, containerID).ExtractErr()
			if mc.ObserveRequest(err) != nil && !cpoerrors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}
