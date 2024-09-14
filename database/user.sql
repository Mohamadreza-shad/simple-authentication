-- name: SignUp :one
INSERT INTO users(
username,
password,
national_code,
phone
) VALUES(
    $1,$2,$3,$4
)
RETURNING *;

-- name: UserByID :one
SELECT * FROM users Where id = $1;

-- name: UserByName :one
SELECT * FROM users Where username = $1;