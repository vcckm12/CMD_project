# -*- coding: utf-8 -*-
"""
[shop_dao.py - 쇼핑몰 데이터베이스(shop.db) 접근 레이어 (DAO)]
- 상품 카탈로그 및 실시간 재고 관리
- 장바구니, 주문 트랜잭션, 배송 추적, 주문 취소
- 정규 프로모션 쿠폰 정책 검증 및 할인 계산
"""

import sqlite3
import os
import uuid
import random
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path

from backend.config import settings


class ShopDAO:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = str(db_path or settings.shop_db_path)
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """쇼핑몰 테이블 스키마 초기화 및 시드 데이터 적재"""
        conn = self._get_conn()
        cur = conn.cursor()

        # 1. 상품 테이블
        cur.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price INTEGER NOT NULL,
                original_price INTEGER,
                stock INTEGER NOT NULL,
                description TEXT,
                image_url TEXT,
                rating REAL DEFAULT 4.8,
                review_count INTEGER DEFAULT 120,
                tags TEXT
            );
        """)

        # 2. 주문 테이블
        cur.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                product_name TEXT NOT NULL,
                product_id INTEGER,
                quantity INTEGER DEFAULT 1,
                total_price INTEGER NOT NULL,
                status TEXT NOT NULL,
                delivery_step INTEGER DEFAULT 2,
                tracking_number TEXT,
                courier TEXT DEFAULT 'CJ대한통운',
                order_date TEXT,
                recipient_address TEXT,
                FOREIGN KEY(product_id) REFERENCES products(id)
            );
        """)

        # 3. 장바구니 테이블
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cart_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(product_id) REFERENCES products(id),
                UNIQUE(user_id, product_id)
            );
        """)

        # 4. 프로모션 쿠폰 테이블
        cur.execute("""
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY,
                discount_type TEXT NOT NULL CHECK(discount_type IN ('PERCENT', 'FIXED_AMOUNT', 'FREE_SHIPPING')),
                discount_value INTEGER NOT NULL,
                min_order_amount INTEGER DEFAULT 0,
                max_discount_amount INTEGER,
                is_active INTEGER DEFAULT 1,
                valid_until TEXT,
                description TEXT
            );
        """)

        # 인덱스 생성
        cur.execute("CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_tracking ON orders(tracking_number);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cart_user ON cart_items(user_id);")

        conn.commit()

        # 시드 데이터 확인 및 주입
        cur.execute("SELECT COUNT(*) AS cnt FROM products;")
        if cur.fetchone()["cnt"] == 0:
            self._seed_default_shop_data(conn)

        # 쿠폰 시드 데이터 확인
        cur.execute("SELECT COUNT(*) AS cnt FROM coupons;")
        if cur.fetchone()["cnt"] == 0:
            self._seed_coupons(conn)

        conn.close()

    def _seed_default_shop_data(self, conn: sqlite3.Connection) -> None:
        """기본 상품 및 주문 데이터 시딩"""
        cur = conn.cursor()
        products = [
            ("오버핏 옥스포드 코튼 셔츠", "상의", 45000, 59000, 25, "부드러운 최고급 면 100% 원단으로 제작된 사계절 데일리 오버핏 셔츠", "/store/images/shirt.jpg", 4.9, 320, "셔츠,상의,오버핏,코튼,면,데일리"),
            ("테이퍼드 밴딩 슬랙스", "하의", 39000, 49000, 18, "신축성 있는 스판 혼방으로 편안한 착용감과 슬림한 실루엣을 제공하는 슬랙스", "/store/images/slacks.jpg", 4.8, 195, "바지,슬랙스,하의,팬츠,밴딩,출근룩"),
            ("헤비웨이트 후드 집업", "아우터", 62000, 78000, 12, "밀도 높은 프리미엄 원단으로 보온성과 각 잡힌 핏을 유지하는 후드 집업", "/store/images/hoodie.jpg", 4.9, 410, "후드,아우터,자켓,집업,맨투맨"),
            ("미니멀 레더 스니커즈", "스니커즈", 89000, 115000, 8, "천연 소가죽과 오솔라이트 인솔을 적용한 극상의 착화감 스니커즈", "/store/images/sneakers.jpg", 4.7, 88, "신발,스니커즈,러닝화,운동화,가죽"),
            ("노이즈캔슬링 블루투스 헤드폰 Pro", "음향기기", 149000, 189000, 15, "하이브리드 액티브 노이즈 캔슬링과 40시간 연속 재생을 지원하는 무선 헤드폰", "/store/images/headphone.jpg", 4.9, 520, "헤드폰,이어폰,음향,음악,무선,블루투스"),
            ("초고속 3in1 맥세이프 무선 충전기", "충전기기", 38000, 48000, 30, "스마트폰, 무선이어폰, 스마트워치를 동시에 15W로 충전하는 멀티 충전 스테이션", "/store/images/charger.jpg", 4.8, 142, "충전기,맥세이프,충전기기,무선충전"),
            ("방수 방오 에브리데이 메신저백", "가방", 54000, 68000, 20, "생활 방수 원단과 16인치 노트북 전용 포켓이 탑재된 기능성 메신저백", "/store/images/bag.jpg", 4.6, 76, "가방,메신저백,크로스백,백팩,노트북가방"),
            ("실키 모달 드레스 삭스 (5팩 세트)", "양말", 15000, 20000, 50, "땀 흡수와 통기성이 우수한 천연 모달 원사 프리미엄 양말 세트", "/store/images/socks.jpg", 4.9, 610, "양말,패션잡화,모달,선물세트")
        ]

        cur.executemany("""
            INSERT INTO products (name, category, price, original_price, stock, description, image_url, rating, review_count, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, products)

        orders = [
            ("ORD-20260914-001", "user_vip_hong", "홍길동", "노이즈캔슬링 블루투스 헤드폰 Pro", 5, 1, 149000, "배송중 (간선상차)", 3, "6890-1234-5678", "CJ대한통운", "2026-09-14 09:30", "서울특별시 강남구 테헤란로 152 강남파이낸스센터 18층"),
            ("ORD-20260912-002", "user_vip_hong", "홍길동", "오버핏 옥스포드 코튼 셔츠", 1, 2, 90000, "배송완료", 4, "6890-9876-5432", "CJ대한통운", "2026-09-12 14:15", "서울특별시 강남구 테헤란로 152 강남파이낸스센터 18층"),
            ("ORD-20260908-003", "user_vip_hong", "홍길동", "헤비웨이트 후드 집업", 3, 1, 62000, "배송완료", 4, "6890-1122-3344", "CJ대한통운", "2026-09-08 11:20", "서울특별시 강남구 테헤란로 152 강남파이낸스센터 18층"),
            ("ORD-20260915-004", "user_general_kim", "김철수", "미니멀 레더 스니커즈", 4, 1, 89000, "상품준비중", 2, "6890-5566-7788", "CJ대한통운", "2026-09-15 16:40", "부산광역시 해운대구 센텀중앙로 78")
        ]

        cur.executemany("""
            INSERT OR REPLACE INTO orders (order_id, user_id, user_name, product_name, product_id, quantity, total_price, status, delivery_step, tracking_number, courier, order_date, recipient_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, orders)

        conn.commit()

    def _seed_coupons(self, conn: sqlite3.Connection) -> None:
        """기본 공식 프로모션 쿠폰 시딩"""
        cur = conn.cursor()
        coupons = [
            ("WELCOME10", "PERCENT", 10, 20000, 10000, 1, "2026-12-31", "신규 가입 고객 10% 할인 쿠폰 (최대 1만원)"),
            ("VIPSTORE", "PERCENT", 15, 50000, 30000, 1, "2026-12-31", "VIP 전용 15% 특별 할인 쿠폰 (최대 3만원)"),
            ("FREESHIP", "FREE_SHIPPING", 3000, 30000, 3000, 1, "2026-12-31", "3만원 이상 구매 시 무료 배송 쿠폰"),
            ("SPRING5K", "FIXED_AMOUNT", 5000, 30000, 5000, 1, "2026-12-31", "봄맞이 5,000원 즉시 할인 쿠폰")
        ]
        cur.executemany("""
            INSERT OR REPLACE INTO coupons (code, discount_type, discount_value, min_order_amount, max_discount_amount, is_active, valid_until, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, coupons)
        conn.commit()

    # =========================================================================
    # 1. 상품(Products) 도메인 로직
    # =========================================================================
    def search_products(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        min_price: Optional[int] = None,
        max_price: Optional[int] = None,
        sort_by: str = "popular",
        in_stock_only: bool = True,
        limit: int = 10,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """상품 카탈로그 다차원 검색 (검색어, 카테고리, 가격대, 정렬, 페이징)"""
        conn = self._get_conn()
        cur = conn.cursor()

        sql = "SELECT id, name, category, price, original_price, stock, description, image_url, rating, review_count, tags FROM products WHERE 1=1"
        params = []

        if in_stock_only:
            sql += " AND stock > 0"

        if min_price is not None and min_price >= 0:
            sql += " AND price >= ?"
            params.append(min_price)

        if max_price is not None and max_price > 0:
            sql += " AND price <= ?"
            params.append(max_price)

        if category:
            sql += " AND (category LIKE ? OR tags LIKE ?)"
            params.extend([f"%{category}%", f"%{category}%"])

        if query:
            sql += " AND (name LIKE ? OR description LIKE ? OR tags LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

        # 정렬 기준 매핑
        if sort_by == "price_asc":
            sql += " ORDER BY price ASC"
        elif sort_by == "price_desc":
            sql += " ORDER BY price DESC"
        elif sort_by == "rating":
            sql += " ORDER BY rating DESC, review_count DESC"
        else: # popular (기본값)
            sql += " ORDER BY review_count DESC, rating DESC"

        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(sql, params)
        rows = cur.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        return results

    def get_product_by_id(self, product_id: int) -> Optional[Dict[str, Any]]:
        """단일 상품 상세 정보 조회"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    # =========================================================================
    # 2. 주문(Orders) 및 결제 트랜잭션 도메인 로직
    # =========================================================================
    def get_user_orders(self, user_id: str, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """특정 사용자의 주문 목록 페이징 조회 (BOLA 방어 연동)"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT order_id, user_id, user_name, product_name, product_id, quantity, total_price, 
                   status, delivery_step, tracking_number, courier, order_date, recipient_address 
            FROM orders 
            WHERE user_id = ? 
            ORDER BY order_date DESC 
            LIMIT ? OFFSET ?
        """, (user_id, limit, offset))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_order_by_id(self, order_id: str) -> Optional[Dict[str, Any]]:
        """단일 주문 상세 조회"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def create_order(
        self,
        user_id: str,
        user_name: str,
        product_id: int,
        quantity: int,
        recipient_address: str,
        coupon_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        신규 주문 생성 트랜잭션 (재고 검증 -> 재고 차감 -> 쿠폰 할인 계산 -> 주문 생성)
        """
        if quantity <= 0:
            return {"success": False, "error": "주문 수량은 1개 이상이어야 합니다."}

        conn = self._get_conn()
        cur = conn.cursor()

        try:
            cur.execute("BEGIN IMMEDIATE;")

            # 1. 상품 및 재고 확인
            cur.execute("SELECT id, name, price, stock FROM products WHERE id = ?", (product_id,))
            product = cur.fetchone()
            if not product:
                conn.rollback()
                conn.close()
                return {"success": False, "error": "존재하지 않는 상품입니다."}

            if product["stock"] < quantity:
                conn.rollback()
                conn.close()
                return {"success": False, "error": f"재고가 부족합니다. (현재 재고: {product['stock']}개)"}

            # 2. 재고 차감
            cur.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (quantity, product_id))

            # 3. 가격 및 쿠폰 할인 계산
            base_total = product["price"] * quantity
            discount_amount = 0
            applied_coupon = None

            if coupon_code:
                cur.execute("SELECT * FROM coupons WHERE code = ? AND is_active = 1", (coupon_code.strip().upper(),))
                cp = cur.fetchone()
                if cp:
                    if base_total >= cp["min_order_amount"]:
                        applied_coupon = cp["code"]
                        if cp["discount_type"] == "PERCENT":
                            discount_amount = int(base_total * (cp["discount_value"] / 100))
                            if cp["max_discount_amount"]:
                                discount_amount = min(discount_amount, cp["max_discount_amount"])
                        elif cp["discount_type"] == "FIXED_AMOUNT":
                            discount_amount = min(cp["discount_value"], base_total)
                        elif cp["discount_type"] == "FREE_SHIPPING":
                            discount_amount = min(cp["discount_value"], 3000)

            final_price = max(0, base_total - discount_amount)

            # 4. 주문 고유 번호 및 운송장 생성
            order_id = f"ORD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            tracking_num = f"6890-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
            order_date = datetime.now().strftime("%Y-%m-%d %H:%M")

            cur.execute("""
                INSERT INTO orders (
                    order_id, user_id, user_name, product_name, product_id, quantity, 
                    total_price, status, delivery_step, tracking_number, courier, 
                    order_date, recipient_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '결제완료 (상품준비중)', 2, ?, 'CJ대한통운', ?, ?)
            """, (
                order_id, user_id, user_name, product["name"], product_id, quantity,
                final_price, tracking_num, order_date, recipient_address
            ))

            conn.commit()
            conn.close()

            return {
                "success": True,
                "order_id": order_id,
                "product_name": product["name"],
                "quantity": quantity,
                "total_price": final_price,
                "discount_amount": discount_amount,
                "applied_coupon": applied_coupon,
                "status": "결제완료 (상품준비중)",
                "tracking_number": tracking_num,
                "courier": "CJ대한통운",
                "order_date": order_date,
                "recipient_address": recipient_address
            }

        except Exception as e:
            conn.rollback()
            conn.close()
            return {"success": False, "error": f"주문 생성 중 오류 발생: {str(e)}"}

    def cancel_order(self, order_id: str, user_id: str) -> Dict[str, Any]:
        """
        주문 취소 트랜잭션 (배송 전 취소 가능, 재고 원복)
        """
        conn = self._get_conn()
        cur = conn.cursor()

        try:
            cur.execute("BEGIN IMMEDIATE;")
            cur.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,))
            order = cur.fetchone()

            if not order:
                conn.rollback()
                conn.close()
                return {"success": False, "error": "해당 주문을 찾을 수 없습니다."}

            if order["user_id"] != user_id:
                conn.rollback()
                conn.close()
                return {"success": False, "error": "다른 사용자의 주문은 취소할 수 없습니다. (BOLA 보호)"}

            # 배송중/배송완료 단계는 직접 취소 불가
            if order["delivery_step"] >= 3 or "배송" in order["status"]:
                conn.rollback()
                conn.close()
                return {
                    "success": False, 
                    "error": f"현재 상태('{order['status']}')에서는 즉시 취소가 불가능합니다. 상품 수령 후 반품/교환을 신청해 주세요."
                }

            if order["status"] == "주문취소 완료":
                conn.rollback()
                conn.close()
                return {"success": False, "error": "이미 취소 완료된 주문입니다."}

            # 1. 재고 원복
            if order["product_id"]:
                cur.execute("UPDATE products SET stock = stock + ? WHERE id = ?", (order["quantity"], order["product_id"]))

            # 2. 주문 상태 변경
            cur.execute("UPDATE orders SET status = '주문취소 완료', delivery_step = 0 WHERE order_id = ?", (order_id,))

            conn.commit()
            conn.close()
            return {
                "success": True, 
                "order_id": order_id, 
                "message": "주문이 성공적으로 취소되었으며 환불 처리가 접수되었습니다."
            }

        except Exception as e:
            conn.rollback()
            conn.close()
            return {"success": False, "error": f"주문 취소 중 오류 발생: {str(e)}"}

    def track_by_tracking_number(self, tracking_number: str) -> Optional[Dict[str, Any]]:
        """운송장 번호 기반 배송 상태 실시간 조회"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM orders WHERE tracking_number = ?", (tracking_number.strip(),))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    # =========================================================================
    # 3. 장바구니(Cart) 도메인 로직
    # =========================================================================
    def get_cart(self, user_id: str) -> Dict[str, Any]:
        """사용자의 장바구니 목록 및 총 결제 예상 금액 조회"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT c.id as cart_id, c.product_id, c.quantity, 
                   p.name, p.price, p.original_price, p.stock, p.image_url,
                   (c.quantity * p.price) as subtotal
            FROM cart_items c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ?
            ORDER BY c.updated_at DESC
        """, (user_id,))
        rows = cur.fetchall()
        conn.close()

        items = [dict(r) for r in rows]
        total_price = sum(item["subtotal"] for item in items)
        total_items = sum(item["quantity"] for item in items)

        return {
            "user_id": user_id,
            "items": items,
            "total_items": total_items,
            "total_price": total_price,
            "shipping_fee": 0 if total_price >= 50000 or total_price == 0 else 3000
        }

    def add_to_cart(self, user_id: str, product_id: int, quantity: int = 1) -> Dict[str, Any]:
        """장바구니 담기 (이미 있으면 수량 누적)"""
        if quantity <= 0:
            return {"success": False, "error": "수량은 1개 이상이어야 합니다."}

        conn = self._get_conn()
        cur = conn.cursor()

        # 상품 존재 여부 및 재고 확인
        cur.execute("SELECT id, name, stock, price FROM products WHERE id = ?", (product_id,))
        p = cur.fetchone()
        if not p:
            conn.close()
            return {"success": False, "error": "존재하지 않는 상품입니다."}

        if p["stock"] < quantity:
            conn.close()
            return {"success": False, "error": f"재고가 부족합니다. (남은 재고: {p['stock']}개)"}

        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO cart_items (user_id, product_id, quantity, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, product_id) DO UPDATE SET
                quantity = quantity + excluded.quantity,
                updated_at = excluded.updated_at
        """, (user_id, product_id, quantity, now, now))

        conn.commit()
        conn.close()
        return {"success": True, "product_name": p["name"], "added_quantity": quantity}

    def remove_from_cart(self, cart_id: int, user_id: str) -> bool:
        """장바구니 항목 삭제 (소유자 확인)"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM cart_items WHERE id = ? AND user_id = ?", (cart_id, user_id))
        deleted = cur.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def clear_cart(self, user_id: str) -> int:
        """장바구니 전체 비우기"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
        cnt = cur.rowcount
        conn.commit()
        conn.close()
        return cnt

    # =========================================================================
    # 4. 쿠폰(Coupons) 및 정책 검증 도메인 로직
    # =========================================================================
    def verify_coupon(self, code: str, order_amount: int) -> Dict[str, Any]:
        """
        공식 쿠폰 유효성 검증 및 실제 할인액 계산 (비즈니스 환각 방어)
        """
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM coupons WHERE code = ? AND is_active = 1", (code.strip().upper(),))
        row = cur.fetchone()
        conn.close()

        if not row:
            return {
                "valid": False,
                "message": f"'{code}'는 유효하지 않거나 만료된 쿠폰 번호입니다."
            }

        cp = dict(row)
        if order_amount < cp["min_order_amount"]:
            return {
                "valid": False,
                "message": f"해당 쿠폰은 최소 {cp['min_order_amount']:,}원 이상 주문 시 사용 가능합니다."
            }

        discount = 0
        if cp["discount_type"] == "PERCENT":
            discount = int(order_amount * (cp["discount_value"] / 100))
            if cp["max_discount_amount"]:
                discount = min(discount, cp["max_discount_amount"])
        elif cp["discount_type"] == "FIXED_AMOUNT":
            discount = min(cp["discount_value"], order_amount)
        elif cp["discount_type"] == "FREE_SHIPPING":
            discount = 3000

        return {
            "valid": True,
            "code": cp["code"],
            "discount_type": cp["discount_type"],
            "discount_amount": discount,
            "description": cp["description"],
            "final_amount": max(0, order_amount - discount)
        }
