# python-jwt-sample-server

## Usage

```bash
poetry install
poetry run jwt-sample-server
```

Then, server is running on http://localhost:8000

Access http://localhost:8000/docs via web browser to see API document.

## Endpoints

### GET /
Sample endpoint. Returns `{"message": "Hello, world!"}`.

```bash
$ curl localhost:8000
{"message":"Hello World"}
```

### POST /token
Get JWT token.

Below users available. Password is `secure` for all users.

- alice
- bob
- eve (Disabled user)

```bash
$ curl localhost:8000/token -d 'username=alice&password=secret'
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTY4NzY2NTY4M30.762CT8j1Lve-KUbGxP2i7agXM0DHf0DjwXjxX9GCzSA","token_type":"bearer"}
```

### GET /private
Private endpoint. Bearer token is required.

Without Bearer token, returns `{"detail": "Not authenticated"}`.
```bash
$ curl localhost:8000/private
{"detail":"Not authenticated"}
```

With Bearer token, returns `{"message": "Hello, private world!"}`.
```bash
$ TOKEN=$(curl localhost:8000/token -d 'username=alice&password=secret' | jq -r .access_token)
$ curl localhost:8000/private -H "Authorization: Bearer $TOKEN"
{"message":"Hello Private World"}
```

With Bearer token of disabled user, returns `{"detail": "Inactive user"}`.
```bash
$ TOKEN=$(curl localhost:8000/token -d 'username=eve&password=secret' | jq -r .access_token)
$ curl localhost:8000/private -H "Authorization: Bearer $TOKEN"
{"detail":"Inactive user"}
```

After 1 minute, Bearer token is expired. Returns `{"detail":"Could not validate credentials"}`.
```bash
$ curl localhost:8000/users/me -H "Authorization: Bearer $TOKEN"
{"detail":"Could not validate credentials"}
```

### GET /users/me
Get current user information.

```bash
$ TOKEN=$(curl localhost:8000/token -d 'username=alice&password=secret' | jq -r .access_token)
$ curl localhost:8000/users/me -H "Authorization: Bearer $TOKEN"
{"username":"alice","email":"alice@example.com","full_name":"alice","disabled":false}

$ TOKEN=$(curl localhost:8000/token -d 'username=bob&password=secret' | jq -r .access_token)
$ curl localhost:8000/users/me -H "Authorization: Bearer $TOKEN"
{"username":"bob","email":"bob@example.com","full_name":"bob","disabled":false}

$ TOKEN=$(curl localhost:8000/token -d 'username=eve&password=secret' | jq -r .access_token)
$ curl localhost:8000/users/me -H "Authorization: Bearer $TOKEN"
{"detail":"Inactive user"}
```
