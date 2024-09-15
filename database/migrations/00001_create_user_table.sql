--liquibase formatted sql

-- changeset reza:1
Create Table if not exists users(
    id bigserial primary key,
    username text not null,
    password text not null,
    national_code varchar(10) null unique,
    phone varchar(11) null,
    email varchar null,
    is_active bool not null default true,
    created_at timestamp not null default now(),
    updated_at timestamp null
)