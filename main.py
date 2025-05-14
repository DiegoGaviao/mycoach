from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastai.text.all import *
import openai
import os

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

# OpenAI Key
openai.api_key = "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"

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

# Carrega modelo
learn = load_learner("model.pkl") if os.path.exists("model.pkl") else None

# Auxiliares
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = get_user(db, username=username)
    db.close()
    if user is None:
        raise credentials_exception
    return user

def fallback_chatgpt(message: str):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Você é um coach motivacional que ajuda o usuário a refletir, propor ações e trazer insights positivos."},
                {"role": "user", "content": message}
            ],
            max_tokens=300,
            temperature=0.7
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return "Não consegui gerar uma resposta personalizada agora. Tente novamente mais tarde."

# Endpoints
@app.post("/register")
def register(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    if get_user(db, form_data.username):
        db.close()
        raise HTTPException(status_code=400, detail="Username already registered")
    user = User(username=form_data.username, hashed_password=get_password_hash(form_data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return {"msg": "User created successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.username})
    db.close()
    return {"access_token": token, "token_type": "bearer"}

@app.post("/mensagem")
def mensagem(data: dict, user: User = Depends(get_current_user)):
    msg = data.get("msg", "")
    if learn:
        pred, _, _ = learn.predict(msg)
        resposta = f"Sua mensagem foi classificada como '{pred}'. Aqui vai uma sugestão personalizada: Continue acreditando em você!"
    else:
        resposta = fallback_chatgpt(msg)

    db = SessionLocal()
    chat = Chat(message=msg, response=resposta, category="Auto" if learn else "GPT", user_id=user.id)
    db.add(chat)
    db.commit()
    db.close()
    return {"mensagem": msg, "categoria": "Auto" if learn else "GPT", "resposta": resposta}

@app.get("/historico")
def historico(user: User = Depends(get_current_user)):
    db = SessionLocal()
    chats = db.query(Chat).filter(Chat.user_id == user.id).all()
    db.close()
    return [
        {
            "mensagem": c.message,
            "categoria": c.category,
            "resposta": c.response,
            "data": c.timestamp
        } for c in chats
    ]
