--liquibase formatted sql

-- changeset reza:1
Create Table if not exists users(
    id bigserial primary key,
    username text not null,
    national_code varchar(10) not null unique,
    phone varchar(11) not null,
    email varchar null,
    is_active boolian not null default true,
    created_at timestamp not null default now(),
    updated_at timestamp null
)