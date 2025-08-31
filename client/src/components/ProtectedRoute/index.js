import React, { useEffect, useState } from "react";
import { Route, Redirect } from "react-router-dom";
import axios from "axios";

const ProtectedRoute = ({ component: Component, ...rest }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

    useEffect(() => {
    const fetchUser = async () => {
        try {
        const response = await axios.get("http://localhost:4000/auth/user", { withCredentials: true });
        setUser(response.data);
      } catch (err) {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

    if (loading) return <p>Loading...</p>;

  return (
    <Route
        {...rest}
        render={(props) =>
        user ? <Component {...props} user={user} /> : <Redirect to="/" />
        }
    />
  );
};

export default ProtectedRoute;
