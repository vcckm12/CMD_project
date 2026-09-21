# -*- coding: utf-8 -*-
"""
[shop_business_test.py - 쇼핑몰 비즈니스 로직 및 가드레일 통합 E2E 검증 테스트]
- 상품 검색, 재고 차감/복구, 장바구니, 주문 생성 및 취소 트랜잭션
- BOLA/IDOR 방어 및 쿠폰 할인 검증
- AI Function Calling 도구 체인 연동 검증
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database.shop_dao import ShopDAO
from backend.services.shop_tools import ShopToolsService


def test_ecommerce_business_flow():
    dao = ShopDAO()
    tools = ShopToolsService(dao=dao)
    test_user = "user_test_runner"
    other_user = "user_victim_bob"

    print("=" * 60)
    print("[E-Commerce Business Logic & Security E2E Test]")
    print("=" * 60)

    # 1. 상품 검색 및 재고 확인
    products = dao.search_products(query="셔츠", limit=5)
    assert len(products) > 0, "No products found for query '셔츠'"
    target_product = products[0]
    initial_stock = target_product["stock"]
    p_id = target_product["id"]
    print(f"[PASS] 1. Product Search: Found '{target_product['name']}' (Stock: {initial_stock}ea, Price: {target_product['price']:,}원)")

    # 2. 쿠폰 유효성 검증
    coupon_res = dao.verify_coupon("WELCOME10", 50000)
    assert coupon_res["valid"], "WELCOME10 coupon should be valid"
    assert coupon_res["discount_amount"] == 5000, f"Expected 5,000 discount, got {coupon_res['discount_amount']}"
    print(f"[PASS] 2. Coupon Validation: WELCOME10 applied (Discount: -{coupon_res['discount_amount']:,}원, Final: {coupon_res['final_amount']:,}원)")

    # 3. 장바구니 담기 및 조회
    dao.clear_cart(test_user)
    cart_add_res = dao.add_to_cart(test_user, p_id, quantity=2)
    assert cart_add_res["success"], "Failed to add item to cart"
    cart = dao.get_cart(test_user)
    assert cart["total_items"] == 2, f"Expected 2 items in cart, got {cart['total_items']}"
    print(f"[PASS] 3. Cart Management: Added 2 items, Cart Subtotal: {cart['total_price']:,}원")

    # 4. 신규 주문 생성 트랜잭션 (재고 차감 검증)
    order_res = dao.create_order(
        user_id=test_user,
        user_name="테스터",
        product_id=p_id,
        quantity=2,
        recipient_address="서울특별시 서초구 반포대로 123",
        coupon_code="WELCOME10"
    )
    assert order_res["success"], f"Order creation failed: {order_res.get('error')}"
    order_id = order_res["order_id"]
    tracking_num = order_res["tracking_number"]

    # 재고 차감 확인
    updated_product = dao.get_product_by_id(p_id)
    assert updated_product["stock"] == initial_stock - 2, f"Stock was not decremented correctly (Expected {initial_stock - 2}, got {updated_product['stock']})"
    print(f"[PASS] 4. Order Created: {order_id} (Tracking: {tracking_num}), Stock decremented: {initial_stock} -> {updated_product['stock']}")

    # 5. 배송 조회
    tracking_info = dao.track_by_tracking_number(tracking_num)
    assert tracking_info is not None, "Tracking number lookup failed"
    assert tracking_info["order_id"] == order_id
    print(f"[PASS] 5. Delivery Tracking: Status '{tracking_info['status']}', Courier '{tracking_info['courier']}'")

    # 6. BOLA 방어 검증 (타인 계정으로 주문 취소 시도 -> 차단되어야 함)
    cancel_hack_res = dao.cancel_order(order_id=order_id, user_id=other_user)
    assert not cancel_hack_res["success"], "BOLA vulnerability: Unauthorized user was able to cancel order!"
    print(f"[PASS] 6. BOLA Defense: Unauthorized cancellation attempt by '{other_user}' safely rejected.")

    # 7. 정상 주문 취소 및 재고 원복 검증
    cancel_res = dao.cancel_order(order_id=order_id, user_id=test_user)
    assert cancel_res["success"], f"Authorized cancellation failed: {cancel_res.get('error')}"
    
    restored_product = dao.get_product_by_id(p_id)
    assert restored_product["stock"] == initial_stock, f"Stock was not restored (Expected {initial_stock}, got {restored_product['stock']})"
    print(f"[PASS] 7. Order Cancellation: Order '{order_id}' canceled and stock restored: {updated_product['stock']} -> {restored_product['stock']}")

    # 8. AI Function Calling 도구 체인 통합 검증
    tool_res = tools.execute_tool("search_products", {"query": "슬랙스", "max_price": 50000}, test_user)
    assert tool_res["status"] == "success", "Tool execution failed"
    print(f"[PASS] 8. AI Tool Dispatcher: 'search_products' returned {tool_res['count']} results successfully.")

    # 9. AI Tool BOLA 실행 차단 검증 (다른 사용자 주문 조회 시도)
    tool_bola_res = tools.execute_tool("get_user_orders", {"user_id": other_user}, test_user)
    assert tool_bola_res["status"] == "blocked", "AI Tool BOLA check failed!"
    print(f"[PASS] 9. AI Tool Guardrail: BOLA violation ({tool_bola_res['violation_type']}) blocked at execution layer.")

    print("=" * 60)
    print("ALL E-COMMERCE BUSINESS LOGIC & GUARDRAIL TESTS PASSED 100%!")
    print("=" * 60)


if __name__ == "__main__":
    test_ecommerce_business_flow()
