from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import openai
import requests

# Configurações iniciais
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# API KEYS
openai.api_key = "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"
deepseek_api_key = "SUA_CHAVE_DEEPSEEK"

# Banco
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
engine = create_engine("sqlite:///database.db")
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    chats = relationship("Chat", back_populates="user")

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True)
    message = Column(Text)
    response = Column(Text)
    category = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="chats")

Base.metadata.create_all(bind=engine)

# 🔥 Fallback múltiplo (OpenAI ➡️ DeepSeek ➡️ Resposta padrão)
def smart_fallback(message: str):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Você é um coach motivacional que ajuda o usuário a refletir, propor ações e trazer insights positivos."},
                {"role": "user", "content": message}
            ],
            max_tokens=300,
            temperature=0.7,
            timeout=15
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ OpenAI falhou: {e}")

    try:
        response = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {deepseek_api_key}"},
            json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "Você é um coach motivacional."},
                    {"role": "user", "content": message}
                ]
            },
            timeout=15
        )
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"❌ DeepSeek falhou: {e}")

    return "Nenhuma IA respondeu no momento. Tente novamente mais tarde."

# Endpoints
@app.post("/register")
def register(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    if db.query(User).filter(User.username == form_data.username).first():
        db.close()
        raise HTTPException(status_code=400, detail="Username already registered")
    user = User(username=form_data.username, hashed_password=pwd_context.hash(form_data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return {"msg": "User created successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(User).filter(User.username == form_data.username).first()
    db.close()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"sub": user.username, "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/mensagem")
def mensagem(data: dict, user: User = Depends(get_current_user)):
    msg = data.get("msg", "")
    resposta = smart_fallback(msg)
    categoria = "IA externa"

    db = SessionLocal()
    chat = Chat(message=msg, response=resposta, category=categoria, user_id=user.id)
    db.add(chat)
    db.commit()
    db.close()
    return {"mensagem": msg, "categoria": categoria, "resposta": resposta}

@app.get("/historico")
def historico(user: User = Depends(get_current_user)):
    db = SessionLocal()
    chats = db.query(Chat).filter(Chat.user_id == user.id).all()
    db.close()
    return [{"mensagem": c.message, "categoria": c.category, "resposta": c.response, "data": c.timestamp} for c in chats]

# Auxiliar
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
    except JWTError:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
