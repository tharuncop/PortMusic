import React, {useEffect, useState} from "react";
import { BrowserRouter as Router, Route, Switch } from "react-router-dom";
import axios from 'axios';

import Navbar from "./components/Navbar";
import LandingPage from "./components/LandingPage";
import Dashboard from "./components/Dashboard";
import './App.css';
import ProtectedRoute from "./components/ProtectedRoute";
import NotFound from "./components/NotFound";

function App() {
  const [user, setUser] = useState(null);
  const [loadingUser, setLoadingUser] = useState(true);

  useEffect(()=>{
    const fetchUser = async() => {
      try{
        const res = await axios.get("http://localhost:4000/auth/user", {withCredentials: true});
        setUser(res.data);
      } catch(err) {
        setUser(null);
      } finally {
        setLoadingUser(false);
      }
    };
    fetchUser();
  }, []);

  const handleLogout = async() => {
    await axios.get("http://localhost:4000/auth/logout", {withCredentials: true});
    setUser(null);
    window.location.href = "/";
  };

  if(loadingUser) return <p>Loading....</p>;

  return (
    <Router>
      <Navbar user={user} onLogout={handleLogout} className = "navbar"/>
      <main className="main-content">
      <Switch>
        <ProtectedRoute exact path='/dashboard' component={Dashboard} user={user} setUser={setUser} />
        <Route exact path="/" component={LandingPage} />

        <Route component={NotFound} />
      </Switch>
      </main>
    </Router>
  );
}

export default App;
