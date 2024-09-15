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

-- name: UpdateUserProfile :exec
UPDATE users
SET 
    national_code = coalesce(sqlc.narg('national_code'), national_code),
    phone = coalesce(sqlc.narg('phone'), phone),
    email = coalesce(sqlc.narg('email'), email)
WHERE id = $1;