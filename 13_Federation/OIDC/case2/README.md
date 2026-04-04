# 実行手順

## 1. Keycloak を起動する

```bash
docker compose up -d
```

## 2. 仮想環境を作成する

```bash
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

## 3. Keycloak を設定する

```bash
python case2_setup_idm_ldap.py
python case2_setup_idp.py
```


## 4. 実験を実行する
```bash
python case2_client.py
```

# 後片付け

```bash
deactivate
docker compose down
rm -rf .env
```