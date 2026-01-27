# NextMavens GraphQL Service

Auto-generated GraphQL API from PostgreSQL schema using Postgraphile.

## Features

- **Auto-generated GraphQL Schema** - Based on your PostgreSQL database
- **JWT Authentication** - Integrates with your auth service
- **Row Level Security (RLS)** - Multi-tenant data isolation
- **GraphiQL IDE** - Interactive GraphQL explorer
- **Real-time Updates** - Ready for subscriptions
- **Mutations & Queries** - Full CRUD operations
- **Relationships** - Auto-detected foreign keys

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `4004` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...` |
| `JWT_SECRET` | Secret for JWT verification | `your-secret` |

## GraphQL Endpoint

```
https://graphql.nextmavens.cloud/graphql
```

## GraphiQL IDE

Interactive GraphQL explorer:
```
https://graphql.nextmavens.cloud/graphiql
```

## Authentication

Include your JWT token in the Authorization header:

```bash
curl https://graphql.nextmavens.cloud/graphql \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id email name } }"}'
```

## Example Queries

### Get all users in your tenant

```graphql
query GetUsers {
  users {
    id
    email
    name
    tenantId
    role
    isVerified
    createdAt
  }
}
```

### Get user by ID

```graphql
query GetUser($id: Int!) {
  userById(id: $id) {
    id
    email
    name
    tenant {
      id
      name
      slug
    }
  }
}
```

### Get tenant info

```graphql
query GetTenants {
  tenants {
    id
    name
    slug
    settings
    createdAt
  }
}
```

### Get user with tenant relation

```graphql
query GetUserWithTenant {
  users(first: 10) {
    id
    email
    name
    tenant {
      id
      name
      slug
    }
  }
}
```

## Example Mutations

### Create a new user (requires tenant context)

```graphql
mutation CreateUser {
  createUser(input: {
    user: {
      email: "newuser@example.com"
      name: "New User"
      passwordHash: "hashed_password"
      tenantId: "your-tenant-uuid"
    }
  }) {
    user {
      id
      email
      name
      tenantId
    }
  }
}
```

### Update a user

```graphql
mutation UpdateUser {
  updateUserById(input: {
    id: 3
    userPatch: {
      name: "Updated Name"
    }
  }) {
    user {
      id
      name
      updatedAt
    }
  }
}
```

### Delete a user

```graphql
mutation DeleteUser {
  deleteUserById(input: { id: 3 }) {
    user {
      id
      email
    }
  }
}
```

## RLS (Row Level Security)

The GraphQL service respects PostgreSQL RLS policies. When you include a valid JWT token:

```javascript
// JWT payload contains:
{
  userId: 3,
  tenantId: "063b49ca-3d34-49c2-b4b9-6dd7800a08d0",
  role: "owner"
}

// PostgreSQL receives these as:
// - role: 'owner'
// - user.id: '3'
// - user.tenant_id: '063b49ca-3d34-49c2-b4b9-6dd7800a08d0'

// RLS policies use current_setting('request.jwt.claim.tenant_id')
```

## Client-side Usage

### Using fetch

```javascript
const query = `
  query GetUsers {
    users {
      id
      email
      name
    }
  }
`;

fetch('https://graphql.nextmavens.cloud/graphql', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({ query })
})
.then(res => res.json())
then(data => console.log(data.data.users));
```

### Using Apollo Client

```javascript
import { ApolloClient, InMemoryCache, HttpLink } from '@apollo/client';

const client = new ApolloClient({
  link: new HttpLink({
    uri: 'https://graphql.nextmavens.cloud/graphql',
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  }),
  cache: new InMemoryCache()
});

// Query
const { data } = await client.query({
  query: gql`
    query GetUsers {
      users {
        id
        email
        name
      }
    }
  `
});

// Mutation
const result = await client.mutate({
  mutation: gql`
    mutation UpdateUser($id: Int!, $name: String!) {
      updateUserById(input: {
        id: $id
        userPatch: { name: $name }
      }) {
        user {
          id
          name
        }
      }
    }
  `,
  variables: { id: 3, name: 'Updated Name' }
});
```

### Using URQL

```javascript
import { createClient, gql } from 'urql';

const client = createClient({
  url: 'https://graphql.nextmavens.cloud/graphql',
  fetchOptions: () => ({
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  })
});

// Query
const { data } = await client.query(gql`
    query GetUsers {
      users {
        id
        email
        name
      }
    }
  `
).toPromise();
```

## Auto-generated Types

Postgraphile automatically creates GraphQL types from your PostgreSQL tables:

### Users Table
```graphql
type User {
  id: Int!
  email: String!
  name: String
  passwordHash: String!
  tenantId: UUID
  role: UserRole
  isVerified: Boolean
  verificationToken: String
  resetPasswordToken: String
  resetPasswordExpires: Datetime
  createdAt: Datetime
  updatedAt: Datetime
  lastLoginAt: Datetime
  tenant: Tenant
}
```

### Tenants Table
```graphql
type Tenant {
  id: UUID!
  name: String!
  slug: String!
  settings: Json
  createdAt: Datetime
  updatedAt: Datetime
  users: [User]!
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/schema` | Database schema info |
| POST | `/graphql` | GraphQL endpoint |
| GET | `/graphiql` | GraphiQL IDE |

## Monitoring

```bash
# Check service health
curl https://graphql.nextmavens.cloud/health

# Get database schema
curl https://graphql.nextmavens.cloud/schema
```

## Integration with Auth Service

1. **Login** to get JWT token
2. **Include token** in Authorization header
3. **RLS policies** automatically filter data by tenant

```bash
# 1. Login
TOKEN=$(curl -s -X POST https://auth.nextmavens.cloud/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' \
  | jq -r '.accessToken')

# 2. Query GraphQL
curl https://graphql.nextmavens.cloud/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id email name } }"}'
```

## Performance Tips

1. **Use field selection** - Only request fields you need
2. **Limit results** - Use `first` and `offset` parameters
3. **Enable query batching** - Combine multiple queries
4. **Use persisted queries** - Cache frequently used queries

### Example with pagination

```graphql
query GetUsersPaginated {
  users(first: 10, offset: 20) {
    id
    email
    name
  }
  usersAggregate {
    aggregate {
      count
    }
  }
}
```

## Advanced Features

### Conditional Fields

```graphql
query GetUsersWithConditionalFields {
  users {
    id
    email
    name
    ...on User {
      isVerified
    }
  }
}
```

### Nested Relations

```graphql
query GetUsersWithTenant {
  users {
    id
    email
    tenant {
      id
      name
      slug
    }
  }
}
```

### Filtering

```graphql
query GetFilteredUsers {
  users(condition: { isVerified: true }) {
    id
    email
    name
  }
}
```

### Ordering

```graphql
query GetUsersOrdered {
  users(orderBy: CREATED_AT_DESC) {
    id
    email
    createdAt
  }
}
```
