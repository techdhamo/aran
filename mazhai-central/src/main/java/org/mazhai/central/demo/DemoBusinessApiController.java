package org.mazhai.central.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Demo Business API Controller
 * 
 * Protected by AranSentinel WAF - demonstrates hardware attestation in action.
 * 
 * These endpoints simulate real fintech business APIs (transfers, payments, etc.)
 * and are used for testing the SDK's AranOmniNet + AranSentinel integration.
 * 
 * Enable with: aran.demo.enabled=true
 */
@RestController
@RequestMapping("/api/v1/business")
@ConditionalOnProperty(name = "aran.demo.enabled", havingValue = "true")
public class DemoBusinessApiController {

    private static final Logger log = LoggerFactory.getLogger(DemoBusinessApiController.class);

    /**
     * Demo: Transfer Funds
     * 
     * Simulates a sensitive banking operation.
     * Protected by AranSentinel WAF - requires hardware-signed Sigil.
     * 
     * Test with:
     * - Mobile app with RASP SDK: ✅ Succeeds (has Sigil)
     * - Postman/curl: ❌ Blocked (no Sigil)
     * - Python bot: ❌ Blocked (cannot forge signature)
     */
    @PostMapping("/transfer-funds")
    public ResponseEntity<TransferResponse> transferFunds(@RequestBody TransferRequest request) {
        log.info("Transfer request: from={}, to={}, amount={}", 
            request.fromAccount(), request.toAccount(), request.amount());

        // Simulate business logic
        String transactionId = "TXN-" + System.currentTimeMillis();
        
        log.info("Transfer successful: txnId={}", transactionId);
        
        return ResponseEntity.ok(new TransferResponse(
            true,
            transactionId,
            "Transfer completed successfully",
            request.amount()
        ));
    }

    /**
     * Demo: Get Account Balance
     * 
     * Simulates a read-only operation.
     * Still protected by WAF to prevent data scraping.
     */
    @GetMapping("/account/{accountId}/balance")
    public ResponseEntity<BalanceResponse> getBalance(@PathVariable String accountId) {
        log.info("Balance request: accountId={}", accountId);

        // Simulate balance lookup
        double balance = 12345.67;
        
        return ResponseEntity.ok(new BalanceResponse(
            accountId,
            balance,
            "USD"
        ));
    }

    /**
     * Demo: Initiate Payment
     * 
     * Simulates a payment gateway operation.
     */
    @PostMapping("/payment/initiate")
    public ResponseEntity<PaymentResponse> initiatePayment(@RequestBody PaymentRequest request) {
        log.info("Payment request: merchant={}, amount={}", 
            request.merchantId(), request.amount());

        String paymentId = "PAY-" + System.currentTimeMillis();
        
        return ResponseEntity.ok(new PaymentResponse(
            paymentId,
            "PENDING",
            "Payment initiated successfully"
        ));
    }

    /**
     * Demo: Update Profile
     * 
     * Simulates a profile update operation.
     */
    @PutMapping("/profile")
    public ResponseEntity<ProfileResponse> updateProfile(@RequestBody ProfileRequest request) {
        log.info("Profile update: userId={}", request.userId());

        return ResponseEntity.ok(new ProfileResponse(
            request.userId(),
            "Profile updated successfully"
        ));
    }

    /**
     * Demo: Get Transaction History
     * 
     * Simulates fetching sensitive transaction data.
     */
    @GetMapping("/transactions")
    public ResponseEntity<TransactionHistoryResponse> getTransactions(
        @RequestParam(defaultValue = "10") int limit
    ) {
        log.info("Transaction history request: limit={}", limit);

        return ResponseEntity.ok(new TransactionHistoryResponse(
            java.util.List.of(
                new Transaction("TXN-001", "Transfer", 100.00, "2026-02-23"),
                new Transaction("TXN-002", "Payment", 50.00, "2026-02-22")
            )
        ));
    }

    // ══════════════════════════════════════════════════════════════════
    // DTOs
    // ══════════════════════════════════════════════════════════════════

    public record TransferRequest(
        String fromAccount,
        String toAccount,
        double amount
    ) {}

    public record TransferResponse(
        boolean success,
        String transactionId,
        String message,
        double amount
    ) {}

    public record BalanceResponse(
        String accountId,
        double balance,
        String currency
    ) {}

    public record PaymentRequest(
        String merchantId,
        double amount,
        String currency
    ) {}

    public record PaymentResponse(
        String paymentId,
        String status,
        String message
    ) {}

    public record ProfileRequest(
        String userId,
        String name,
        String email
    ) {}

    public record ProfileResponse(
        String userId,
        String message
    ) {}

    public record Transaction(
        String id,
        String type,
        double amount,
        String date
    ) {}

    public record TransactionHistoryResponse(
        java.util.List<Transaction> transactions
    ) {}
}
