import pandas as pd
import os
import sys

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

if __name__ == "__main__":
    convert_xlsx_to_js()