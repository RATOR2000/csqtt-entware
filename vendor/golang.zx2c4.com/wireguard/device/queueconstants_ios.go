//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// Fit within memory limits for iOS's Network Extension API, which has stricter requirements.
// These are vars instead of consts, because heavier network extensions might want to reduce
// them further.
var (
	QueueStagedSize                   = 64
	QueueOutboundSize                 = 64
	QueueInboundSize                  = 64
	QueueHandshakeSize                = 64
	PreallocatedBuffersPerPool uint32 = 512
)

const MaxSegmentSize = 2048
