-- name: CreateUser :one
INSERT INTO users(
username,
national_code,
phone
) VALUES(
    $1,$2,$3
)
RETURNING *;

-- name: User :one
SELECT * FROM users Where id = $1;