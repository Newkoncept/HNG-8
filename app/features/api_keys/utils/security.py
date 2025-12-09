# from passlib.context import CryptContext

# pwd_context = CryptContext(
#     schemes=["bcrypt"],
#     deprecated="auto"
# )

# def hash_key(raw_key: str) -> str:
#     return pwd_context.hash(raw_key)

# def verify_key(raw_key: str, hashed_key: str) -> bool:
#     return pwd_context.verify(raw_key, hashed_key)



from passlib.hash import argon2

def hash_key(secret: str) -> str:
    return argon2.using(rounds=3, memory_cost=102400, parallelism=8).hash(secret)

def verify_key(secret: str, hashed: str) -> bool:
    return argon2.verify(secret, hashed)