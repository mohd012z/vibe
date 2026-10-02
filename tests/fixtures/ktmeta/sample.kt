package com.fatah.vibetest

sealed class Order {
    data class Paid(val amountCents: Int, val sku: String) : Order()
    data class Refunded(val orderId: Long, val reason: String) : Order()
}

interface PaymentGateway {
    fun authorize(token: String, amountCents: Int): Boolean
    fun settle(orderId: Long)
}

class CheckoutService(val gateway: PaymentGateway) {
    private var totalCents = 0
    fun charge(sku: String, cents: Int): Order {
        totalCents += cents
        return if (gateway.authorize("tok", cents)) {
            Order.Paid(cents, sku)
        } else {
            Order.Refunded(0L, "declined")
        }
    }
    companion object {
        const val MAX_CENTS = 10_000_000
    }
}
