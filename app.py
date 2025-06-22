from flask import Flask, render_template, jsonify, request, session
import os
import base64
from webauthn import verify_registration_response,verify_authentication_response

app = Flask(__name__)
app.secret_key = 'secret_key'

users = {}

@app.route('/')
def index():
    return render_template('test_index.html')

@app.route('/new')
def new():
    return render_template('test_new.html')

@app.route('/login')
def login():
    return render_template('test_login.html')

@app.route('/api/new', methods=['POST'])
def register_options():
    username = request.json.get("username")
    challenge = os.urandom(32)
    challenge_b64url = base64.urlsafe_b64encode(challenge).rstrip(b'=').decode()
    user_id_b64url = base64.urlsafe_b64encode(username.encode()).rstrip(b'=').decode()

    print("【Pythonサーバ】発行challenge:", challenge_b64url)

    options = {
        "rp": {"name": "Test App"},
        "user": {
            "id": user_id_b64url,
            "name": username,
            "displayName": username
        },
        "challenge": challenge_b64url,
        "pubKeyCredParams": [
            {"alg": -7, "type": "public-key"}
        ],
        "authenticatorSelection": {
            "userVerification": "preferred",
            "residentKey": "required",  # Discoverable Credentialsを要求
            "requireResidentKey": True  # 従来のブラウザとの互換性のため
        },
        "timeout": 60000,
        "attestation": "direct"
    }
    session["challenge"] = challenge  # ←bytesで保存
    session["username"] = username
    return jsonify(options)

@app.route('/api/submit', methods=['POST'])
def register_verify():
    import json
    data = request.get_json()
    credential = data.get("credential")
    username = data.get("username")

    expected_challenge = session.get("challenge")  # ←bytesで取得
    print("【Pythonサーバ】セッションchallenge(bytes):", expected_challenge)
    print("【Pythonサーバ】セッションchallenge(b64):", base64.urlsafe_b64encode(expected_challenge).rstrip(b'=').decode())

    # clientDataJSONをデコードしてchallenge確認
    client_data_json_b64url = credential["response"]["clientDataJSON"]
    pad = '=' * (-len(client_data_json_b64url) % 4)
    client_data_json_bytes = base64.urlsafe_b64decode(client_data_json_b64url + pad)
    client_data = json.loads(client_data_json_bytes.decode())
    print("【Pythonサーバ】clientDataJSON.challenge:", client_data["challenge"])

    if not credential or not username:
        return jsonify({"success": False, "error": "データが足りません"})

    if not expected_challenge:
        return jsonify({"success": False, "error": "チャレンジが見つかりません"})

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,  # ←bytesでOK
            expected_rp_id="localhost",
            expected_origin="http://localhost:9200",
            require_user_verification=True,
        )

        users[username] = {
            "credential_id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
        }

        return jsonify({"success": True})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)})
    
    
@app.route('/api/login/options', methods=['POST'])
def login_options():
    # Discoverable Credentialsの場合、usernameは不要
    # ただし、既存のUIとの互換性のため、受け取りは可能にしておく
    username = request.json.get("username", "")

    challenge = os.urandom(32)
    challenge_b64url = base64.urlsafe_b64encode(challenge).rstrip(b'=').decode()
    session["challenge"] = challenge
    if username:
        session["username"] = username

    options = {
        "challenge": challenge_b64url,
        "timeout": 60000,
        "rpId": "localhost",
        "userVerification": "preferred",
        # Discoverable Credentialsでは allowCredentials を空にする
        # これにより認証器が保存されているクレデンシャルから適切なものを選択する
        "allowCredentials": []
    }
    return jsonify(options)

@app.route('/api/login/verify', methods=['POST'])
def login_verify():
    import json
    data = request.get_json()
    credential = data.get("credential")
    
    if not credential:
        return jsonify({"success": False, "error": "クレデンシャルが不足しています"})

    expected_challenge = session.get("challenge")

    # Discoverable Credentialsの場合、credential_idからユーザーを特定
    credential_id = base64.urlsafe_b64decode(credential["id"] + "==")
    
    # 登録されているユーザーからマッチするクレデンシャルIDを探す
    username = None
    user = None
    for stored_username, stored_user in users.items():
        if stored_user["credential_id"] == credential_id:
            username = stored_username
            user = stored_user
            break
    
    if not user:
        return jsonify({"success": False, "error": "クレデンシャルが見つかりません"})

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id="localhost",
            expected_origin="http://localhost:9200",
            credential_public_key=user["public_key"],
            credential_current_sign_count=user["sign_count"],
            require_user_verification=True
        )

        # サインカウント更新
        users[username]["sign_count"] = verification.new_sign_count
        
        # セッションにユーザー名を保存
        session["username"] = username

        return jsonify({"success": True, "username": username})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/login/discoverable', methods=['POST'])
def login_discoverable():
    """
    Discoverable Credentials専用のログインエンドポイント
    ユーザー名を指定せずにログインする
    """
    challenge = os.urandom(32)
    challenge_b64url = base64.urlsafe_b64encode(challenge).rstrip(b'=').decode()
    session["challenge"] = challenge

    options = {
        "challenge": challenge_b64url,
        "timeout": 60000,
        "rpId": "localhost",
        "userVerification": "preferred",
        "allowCredentials": []  # 空の配列でDiscoverable Credentialsを使用
    }
    return jsonify(options)

if __name__ == '__main__':
    app.run(debug=True, port=9200, host='0.0.0.0')
