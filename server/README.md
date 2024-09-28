## API Features

### User Management
- **User Registration**: Allows users to register by providing their name, email, and password. Passwords are hashed for security.
- **User Login**: Authenticates users and provides a JWT token for secure access.
- **User Logout**: Logs out the user by clearing the authentication cookie.
- **Fetch Users**: Retrieves a list of all registered users.
- **Show User**: Fetches details of a specific user by their ID.
- **Update User**: Allows users to update their profile details including their name and password.
- **Delete User**: Deletes a user's account.

### Post Management
- **Create Post**: Allows authenticated users to create a new post with a title and description.
- **Fetch Posts**: Retrieves a paginated list of all posts, including comments and the names of users who made the comments.
- **Search Posts**: Searches posts based on their description.
- **Show Post**: Fetches details of a specific post by its ID.
- **Delete Post**: Allows the owner of a post to delete it.

### Comment Management
- **Create Comment**: Allows authenticated users to add a comment to a post.
- **Fetch Comments**: Retrieves a list of comments for a specific post.
- **Show Comment**: Fetches details of a specific comment by its ID.
- **Delete Comment**: Allows the owner of a comment to delete it.

### To set up express-prisma-postgresql backend follow my blog on dev community

```
https://dev.to/ajor-saha/setting-up-a-backend-with-prisma-express-and-postgresql-482e
```