// import React, { useEffect, useState } from "react";
import axios from "axios";
import { useHistory } from "react-router-dom";

function Dashboard({user}) {

  const history = useHistory();

  const handleLogout = async () => {
    await axios.get("http://localhost:4000/auth/logout", { withCredentials: true });
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
