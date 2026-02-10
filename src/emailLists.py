import pandas as pd
import requests

def get_disposable_domains():
    print("최신 익명 메일 리스트 로딩 중...")
    url = "https://raw.githubusercontent.com/miketheman/disposable-email-domains/master/disposable_email_blocklist.conf"
    try:
        response = requests.get(url)
        return set(line.strip().lower() for line in response.text.splitlines() if line.strip())
    except:
        return set()

def analyze_large_csv(input_file, output_file):
    disposable_set = get_disposable_domains()
    
    # 공듓님이 찾으시는 "무료/보안/익명" 서비스들 수동 추가
    anonymous_privacy_services = {
        'proton.me', 'protonmail.com', 'protonmail.ch', 'tutanota.com', 'tuta.io',
        'riseup.net', 'mailfence.com', 'cock.li', 'guerrillamail.com', 'yopmail.com',
        'temp-mail.org', 'mailinator.com', 'dispostable.com', '10minutemail.com'
    }

    chunk_size = 100000 
    first_chunk = True

    # 인코딩 문제를 방지하기 위해 encoding='utf-8-sig' 또는 'cp949' 사용
    for chunk in pd.read_csv(input_file, chunksize=chunk_size, encoding='utf-8-sig', on_bad_lines='skip'):
        # 도메인 추출 및 전처리
        chunk['domain'] = chunk['email'].astype(str).str.split('@').str[-1].str.strip().str.lower()
        
        # 분류 로직
        # 1. 일회용 리스트에 있는가? OR 2. 우리가 정한 익명/보안 서비스인가?
        chunk['is_anonymous'] = chunk['domain'].apply(
            lambda x: x in disposable_set or x in anonymous_privacy_services
        )
        
        # 일반 대형 포털 분류
        common_portals = {'gmail.com', 'naver.com', 'daum.net', 'kakao.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'yandex.ru', 'mail.ru'}
        chunk['category'] = 'Company/Private'
        chunk.loc[chunk['is_anonymous'], 'category'] = 'Anonymous/Privacy Service'
        chunk.loc[chunk['domain'].isin(common_portals), 'category'] = 'Public Portal'

        # 결과 저장
        mode = 'w' if first_chunk else 'a'
        header = True if first_chunk else False
        chunk.to_csv(output_file, mode=mode, index=False, header=header, encoding='utf-8-sig')
        first_chunk = False
        print(f"진행 중... 처리 완료")

    print(f"✨ 분석 끝! '{output_file}'을 확인하세요.")

analyze_large_csv(r'C:\Users\snlee\Downloads\DataAnalysis\src\email.csv', 'free_domain.csv')