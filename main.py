from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import openai
import os

app = FastAPI()

# CORS seguro para seu domínio customizado
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mycoach.dhawk.com.br"],  # coloque seu domínio aqui SEM BARRA FINAL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock banco de usuários
fake_users_db = {
    "kaka": {
        "username": "kaka",
        "full_name": "Kaka User",
        "hashed_password": "1234",  # apenas exemplo inseguro, troque por hash real
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelo de usuário
class User(BaseModel):
    username: str
    full_name: str | None = None

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password  # ⚠️ apenas para teste, use bcrypt em produção

def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return User(username=user["username"], full_name=user["full_name"])

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": user.username, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    user = fake_users_db.get(token)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário inválido")
    return User(username=user["username"], full_name=user["full_name"])

# Fallback seguro com OpenAI e DeepSeek
OPENAI_KEY = os.getenv("OPENAI_API_KEY") or "sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY") or "ds-XXXXXXXXXXXXXXXXXXXXXXXXXXXX"

async def fallback_chat(prompt):
    try:
        # Tenta OpenAI primeiro
        openai.api_key = OPENAI_KEY
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )
        return response['choices'][0]['message']['content']
    except Exception:
        try:
            # Tenta DeepSeek se OpenAI falhar
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {DEEPSEEK_KEY}"},
                    json={
                        "model": "deepseek-chat",
                        "messages": [{"role": "user", "content": prompt}],
                    }
                )
                return response.json()["choices"][0]["message"]["content"]
        except Exception:
            return "Erro no fallback automático."

@app.post("/chat")
async def chat_endpoint(payload: dict):
    prompt = payload.get("prompt", "")
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt não informado")
    resposta = await fallback_chat(prompt)
    return {"resposta": resposta}
