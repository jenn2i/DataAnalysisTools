import pandas as pd
import os
import sys

<<<<<<< HEAD
current_dir = os.path.dirname(os.path.abspath(__file__))

# 🔥 합칠 엑셀 파일들 (파일명을 정확히 확인하세요!)
input_filenames = [
    "regip_tags_results_B.xlsx", 
    "lastip_tags_results_B.xlsx"
]

output_filename = "ip_database.js"
output_file = os.path.join(current_dir, output_filename)

def convert_xlsx_to_js():
    js_content = "export const IP_THREAT_DB = {\n"
    total_count = 0
    
    print(f"🚀 변환 시작! 대상 파일: {len(input_filenames)}개")
    print(f"🎯 필터링 모드: 오직 [vpn, tor, proxy] 태그만 남깁니다.\n")

    for filename in input_filenames:
        input_path = os.path.join(current_dir, filename)
        print(f"🔄 Reading '{filename}'...")

        if not os.path.exists(input_path):
            print(f"   ❌ 오류: 파일을 찾을 수 없습니다. (경로: {input_path})")
            continue

        try:
            df = pd.read_excel(input_path, engine='openpyxl')
            if df.empty:
                print("   ⚠️ 경고: 데이터가 비어있습니다.")
                continue

            # 컬럼 찾기
            col_ip = next((c for c in df.columns if 'ip' in c.lower()), None)
            col_country = next((c for c in df.columns if 'country' in c.lower() or 'code' in c.lower()), None)
            col_tags = next((c for c in df.columns if 'tag' in c.lower() or 'type' in c.lower()), None)

            if not col_ip:
                print(f"   ❌ 오류: IP 컬럼을 찾을 수 없습니다.")
                continue

            print(f"   ℹ️ 매핑: IP=[{col_ip}], Country=[{col_country}], Tags=[{col_tags}]")

            df = df.fillna('')
            file_count = 0

            for _, row in df.iterrows():
                ip = str(row[col_ip]).strip()
                if not ip: continue

                country = str(row[col_country]).strip() if col_country else ''
                
                # 🔥 [핵심] 태그 필터링 로직 (여기서 다 걸러냄)
                raw_tag = str(row[col_tags]).strip().lower() if col_tags else ''
                final_tag = ""

                if "vpn" in raw_tag:
                    final_tag = "vpn"
                elif "tor" in raw_tag:
                    final_tag = "tor"
                elif "proxy" in raw_tag:
                    final_tag = "proxy"
                # 그 외(self-signed, suspicious 등)는 전부 ""(빈칸) 처리됨

                js_content += f'    "{ip}": {{ country: "{country}", tags: "{final_tag}" }},\n'
                file_count += 1
            
            print(f"   ✅ 성공! {file_count}개 데이터 처리됨.\n")
            total_count += file_count

        except Exception as e:
            print(f"   ❌ 처리 중 오류: {e}\n")

    js_content += "};\n"

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(js_content)

        print("=" * 40)
        print(f"🎉 전체 통합 완료!")
        print(f"🧹 태그 정제 완료 (VPN/TOR/PROXY만 유지)")
        print(f"📊 총 IP 개수: {total_count:,}개")
        print(f"📂 생성된 파일: {output_file}")
        print("=" * 40)
    except Exception as e:
        print(f"❌ 파일 저장 실패: {e}")
=======
# ==========================================
# 1. 경로 강제 보정 (핵심!)
# ==========================================
# 현재 이 파이썬 파일(ip_db.py)이 있는 진짜 폴더 위치를 가져옵니다.
current_dir = os.path.dirname(os.path.abspath(__file__))

# 엑셀 파일명 (파일명이 정확한지 꼭 확인하세요!)
input_filename = "regip_tags_results_B.xlsx"
output_filename = "ip_database.js"

# 경로 합치기 (폴더 경로 + 파일명) -> 이제 어디서 실행하든 상관없습니다.
input_file = os.path.join(current_dir, input_filename)
output_file = os.path.join(current_dir, output_filename)

# ==========================================
# 2. 변환 로직
# ==========================================
def convert_xlsx_to_js():
    # 디버깅용: 어디를 찾고 있는지 눈으로 확인
    print(f"📍 파이썬 파일 위치: {current_dir}")
    print(f"🔎 엑셀 파일 찾는 곳: {input_file}")
    
    if not os.path.exists(input_file):
        print(f"\n❌ 오류: '{input_filename}' 파일을 찾을 수 없습니다.")
        print(f"   -> 위 '엑셀 파일 찾는 곳' 경로에 파일이 진짜 있는지 확인해주세요.")
        return

    print(f"🔄 '{input_filename}' 읽는 중... (Excel 모드)")

    try:
        # 엑셀 읽기
        df = pd.read_excel(input_file, engine='openpyxl')
        
        if df.empty:
            print("❌ 오류: 엑셀 파일은 찾았는데 내용이 비어있습니다.")
            return

        # 컬럼 찾기 (대소문자 무시)
        cols = df.columns.str.lower()
        col_ip = next((c for c in df.columns if 'ip' in c.lower()), None)
        col_country = next((c for c in df.columns if 'country' in c.lower() or 'code' in c.lower()), None)
        col_tags = next((c for c in df.columns if 'tag' in c.lower() or 'type' in c.lower()), None)

        if not col_ip:
            print(f"❌ 오류: 'IP' 컬럼을 찾을 수 없습니다. (발견된 컬럼: {list(df.columns)})")
            return

        print(f"ℹ️ 매핑 성공: IP=[{col_ip}], Country=[{col_country}], Tags=[{col_tags}]")

        # JS 파일 작성
        js_content = "export const IP_THREAT_DB = {\n"
        count = 0
        
        # 빈값 채우기
        df = df.fillna('')

        for _, row in df.iterrows():
            ip = str(row[col_ip]).strip()
            if not ip: continue

            country = str(row[col_country]).strip() if col_country else ''
            tags = str(row[col_tags]).strip() if col_tags else ''

            js_content += f'    "{ip}": {{ country: "{country}", tags: "{tags}" }},\n'
            count += 1

        js_content += "};\n"

        # 파일 저장
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(js_content)

        print("-" * 40)
        print(f"🎉 변환 대성공! 총 {count}개의 IP가 등록되었습니다.")
        print(f"📂 생성된 파일: {output_file}")
        print("-" * 40)

    except Exception as e:
        print(f"\n❌ 치명적 오류 발생: {e}")
        print("💡 팁: 혹시 파일은 있는데 읽기 에러가 나면, 실제로는 CSV 파일일 수도 있습니다.")
>>>>>>> fa9410b2594e52948dc42a8d89a9872d1683c310

if __name__ == "__main__":
    convert_xlsx_to_js()