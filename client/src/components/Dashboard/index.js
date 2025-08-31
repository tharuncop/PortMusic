import React, { useEffect, useState } from "react";
import axios from "axios";
import { useHistory } from "react-router-dom";

function Dashboard() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const history = useHistory();

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await axios.get("http://localhost:4000/auth/user", { withCredentials: true });
        setUser(response.data);
      } catch (err) {
        console.error("Error fetching user: ", err);
        history.push('/');
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [history]);

  if (loading) return <p>Loading...</p>;
  if (!user) return null;

  const handleLogout = async () => {
    await axios.get("http://localhost:4000/auth/logout", { withCredentials: true });
    setUser(null);
    history.push("/");
  };

  return (
    <div>
      <h1>Welcome, {user.displayName}</h1>
      <p>Email: {user.emails[0].value}</p>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
}

export default Dashboard;
