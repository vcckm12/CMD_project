import sqlite3
import sys
import os

# UTF-8 출력 보장
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

DB_PATH = os.path.join(os.path.dirname(__file__), "company.db")

def print_table(headers, rows):
    if not rows:
        print("조회 결과가 없습니다.\n")
        return
    
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            length = len(str(val))
            if length > col_widths[i]:
                col_widths[i] = length
    
    header_str = " | ".join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_str = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_str)
    print(sep_str)
    
    for row in rows:
        row_str = " | ".join(str(val if val is not None else "").ljust(col_widths[i]) for i, val in enumerate(row))
        print(row_str)
    print(f"\n(총 {len(rows)}건)\n")

def run_query(cur, conn, query):
    try:
        cur.execute(query)
        if cur.description:
            headers = [d[0] for d in cur.description]
            rows = cur.fetchall()
            print_table(headers, rows)
        else:
            conn.commit()
            print(f"쿼리가 성공적으로 실행되었습니다. (영향받은 행: {cur.rowcount}개)\n")
    except Exception as e:
        print(f"[오류] {e}\n")

def main():
    if not os.path.exists(DB_PATH):
        print(f"데이터베이스 파일({DB_PATH})을 찾을 수 없습니다.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        run_query(cur, conn, query)
    else:
        # Default: show all employees and enter interactive mode
        print("=" * 65)
        print(" [한국테크 임직원 명부 데이터베이스 (company.db)]")
        print("=" * 65)
        run_query(cur, conn, "SELECT id AS 사번, name AS 이름, department AS 부서, position AS 직급, phone AS 전화번호, salary_text AS 연봉 FROM employees")
        
        print("-" * 65)
        print("SQL 쿼리를 직접 입력하여 조회할 수 있습니다. (종료: exit 또는 quit)")
        print("예시: SELECT * FROM employees WHERE department = '개발팀'")
        print("-" * 65)
        
        while True:
            try:
                user_input = input("sqlite> ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ('exit', 'quit', '.exit', '.quit'):
                    print("종료합니다.")
                    break
                run_query(cur, conn, user_input)
            except (KeyboardInterrupt, EOFError):
                print("\n종료합니다.")
                break
                
    conn.close()

if __name__ == '__main__':
    main()
