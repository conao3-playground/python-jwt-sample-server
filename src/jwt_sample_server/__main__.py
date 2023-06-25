import fastapi
import uvicorn

app = fastapi.FastAPI()


@app.get('/')
def root():
    return {'message': 'Hello World'}


def main():
    uvicorn.run('jwt_sample_server.__main__:app', reload=True)
