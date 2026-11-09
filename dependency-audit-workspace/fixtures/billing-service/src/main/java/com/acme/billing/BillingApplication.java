package com.acme.billing;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class BillingApplication {
    private static final Logger LOG = LogManager.getLogger(BillingApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(BillingApplication.class, args);
    }

    @GetMapping("/invoices")
    public String invoices(@RequestHeader("User-Agent") String userAgent) {
        LOG.info("Invoice list requested by {}", userAgent);
        return "[]";
    }
}
