package com.taobao.search;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 淘宝搜索/拍立淘链路模拟服务。
 *
 * 基于开源 unidbg-server (cxapython/unidbg-server) 的 SpringBoot 骨架改造：
 *  - config/TaobaoSignConfiguration: 创建 AndroidEmulator + VM，加载 libsgmain.so
 *  - sign/MtopSigner: 可插拔签名后端（unidbg 真实模拟 / mock 离线）
 *  - service: MTOP 请求编排 + 人类行为模拟 + 响应解析
 *  - controller: /api/search, /api/image_search, /api/health
 */
@SpringBootApplication
public class TaobaoSearchApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaobaoSearchApplication.class, args);
    }
}
