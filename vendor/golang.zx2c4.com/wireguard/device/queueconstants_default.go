//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// CSQTT Entware bounded, single-peer/BatchSize-1 profile. See internal/wgbridge/README.md.
const (
	QueueStagedSize            = 64
	QueueOutboundSize          = 64
	QueueInboundSize           = 64
	QueueHandshakeSize         = 64
	MaxSegmentSize             = 2048
	PreallocatedBuffersPerPool = 512
)
