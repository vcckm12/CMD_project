# -*- coding: utf-8 -*-
"""
[company_dao.py - 사내 임직원 데이터베이스(company.db) 연동 모듈]
- 한국테크 임직원 명부(company.db)를 조회하고 챗봇 서비스 및 RAG/가드레일 검증에 연동합니다.
"""

import sqlite3
import os
from typing import List, Dict, Any, Optional

class CompanyDB:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "company.db")
        self.db_path = db_path

    def get_all_employees(self) -> List[Dict[str, Any]]:
        """전체 임직원 명부 조회"""
        if not os.path.exists(self.db_path):
            return []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM employees ORDER BY id ASC")
            return [dict(r) for r in cur.fetchall()]

    def search_employee(self, query: str) -> List[Dict[str, Any]]:
        """이름 또는 부서로 임직원 검색"""
        if not os.path.exists(self.db_path):
            return []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            param = f"%{query}%"
            cur.execute("SELECT * FROM employees WHERE name LIKE ? OR department LIKE ? OR position LIKE ?", (param, param, param))
            return [dict(r) for r in cur.fetchall()]
