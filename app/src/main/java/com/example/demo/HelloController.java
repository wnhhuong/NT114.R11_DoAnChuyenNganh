package com.example.demo;

import java.util.concurrent.ThreadLocalRandom;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    // Tỉ lệ lỗi giả lập (0..1) để thử Argo Rollouts tự rollback; mặc định 0
    @Value("${demo.error-rate:0}")
    private double errorRate;

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        if (errorRate > 0 && ThreadLocalRandom.current().nextDouble() < errorRate) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Injected error");
        }
        return ResponseEntity.ok("Hello World");
    }
}
