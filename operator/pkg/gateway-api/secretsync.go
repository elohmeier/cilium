// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func EnqueueTLSSecrets(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return nil
		}

		var reqs []reconcile.Request
		for _, l := range gw.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					continue
				}
				s := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(cert.Namespace, gw.Namespace),
					Name:      string(cert.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: s})
				scopedLog.Debug("Enqueued secret for gateway", logfields.Secret, s)
			}
		}
		return reqs
	})
}

func IsReferencedByCiliumGateway(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	gateways := getGatewaysForSecret(ctx, c, obj, logger)
	for _, gw := range gateways {
		if hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return true
		}
	}

	return false
}

// EnqueueFrontendTLSConfigMaps returns an event handler that enqueues ConfigMaps
// referenced in Gateway.Spec.Listeners[].TLS.FrontendValidation.CACertificateRefs.
func EnqueueFrontendTLSConfigMaps(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return nil
		}

		var reqs []reconcile.Request
		for _, l := range gw.Spec.Listeners {
			if l.TLS == nil || l.TLS.FrontendValidation == nil {
				continue
			}
			for _, ref := range l.TLS.FrontendValidation.CACertificateRefs {
				// Only handle ConfigMap references
				if ref.Group != "" || ref.Kind != "ConfigMap" {
					continue
				}
				cfgMap := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(ref.Namespace, gw.Namespace),
					Name:      string(ref.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: cfgMap})
				scopedLog.Debug("Enqueued frontend TLS configmap for gateway", "configmap", cfgMap)
			}
		}
		return reqs
	})
}

// FrontendTLSConfigMapIsReferenced returns true if the ConfigMap is referenced by
// a Cilium Gateway's FrontendValidation configuration.
func FrontendTLSConfigMapIsReferenced(ctx context.Context, c client.Client, logger *slog.Logger, cfgMap *corev1.ConfigMap) bool {
	gateways := getGatewaysForFrontendTLSConfigMap(ctx, c, cfgMap, logger)
	for _, gw := range gateways {
		if hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return true
		}
	}

	return false
}
