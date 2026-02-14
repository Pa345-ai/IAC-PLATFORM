CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE action_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE goals (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    target_value FLOAT NOT NULL,
    current_value FLOAT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'IN_PROGRESS'
);

CREATE TABLE trust_levels (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    current_level VARCHAR(20) DEFAULT 'ASK',
    success_count INT DEFAULT 0,
    failure_count INT DEFAULT 0
);
