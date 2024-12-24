// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PTP 1588 clock support - support for timestamping in PHY devices
 *
 * Copyright (C) 2010 OMICRON electronics GmbH
 */
#include <linux/errqueue.h>
#include <linux/phy.h>
#include <linux/ptp_classify.h>
#include <linux/skbuff.h>
#include <linux/export.h>

static unsigned int classify(const struct sk_buff *skb)
{
	if (likely(skb->dev && skb->dev->phydev &&
		   skb->dev->phydev->mii_ts))
		return ptp_classify_raw(skb);
	else
		return PTP_CLASS_NONE;
}

void skb_clone_tx_timestamp(struct sk_buff *skb)
{
	struct mii_timestamper *mii_ts;
	struct sk_buff *clone;
	unsigned int type;

	if (!skb->sk)
		return;

	type = classify(skb);
	if (type == PTP_CLASS_NONE)
		return;

	mii_ts = skb->dev->phydev->mii_ts;
	if (likely(mii_ts->txtstamp)) {
		clone = skb_clone_sk(skb);
		if (!clone)
			return;
		mii_ts->txtstamp(mii_ts, clone, type);
	}
}
EXPORT_SYMBOL_GPL(skb_clone_tx_timestamp);

//通过对数据包类型的检测，决定是否通过网络设备的 PHY（物理层）硬件时间戳功能为数据包添加时间戳
bool skb_defer_rx_timestamp(struct sk_buff *skb)
{
	struct mii_timestamper *mii_ts;
	unsigned int type;

	//// 检查是否有有效的设备、PHY设备以及物理设备的时间戳处理器
	if (!skb->dev || !skb->dev->phydev || !skb->dev->phydev->mii_ts)
		return false;

	//检查 skb 的头部空间是否足够
	if (skb_headroom(skb) < ETH_HLEN)
		return false;

	//给 skb 增加 Ethernet header 空间
	__skb_push(skb, ETH_HLEN);

	//使用 PTP 分类函数确定数据包的时间戳类型
	type = ptp_classify_raw(skb);

	__skb_pull(skb, ETH_HLEN);

	// 如果数据包不需要时间戳，则返回 false
	if (type == PTP_CLASS_NONE)
		return false;

	//获取物理设备的时间戳器
	mii_ts = skb->dev->phydev->mii_ts;
	//如果支持接收时间戳功能，则调用它来处理时间戳
	if (likely(mii_ts->rxtstamp))
		return mii_ts->rxtstamp(mii_ts, skb, type);

	return false;
}
EXPORT_SYMBOL_GPL(skb_defer_rx_timestamp);
