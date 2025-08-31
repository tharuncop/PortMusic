import React from "react";
import { BrowserRouter as Router, Route, Switch } from "react-router-dom";

import Navbar from "./components/Navbar";
import LandingPage from "./components/LandingPage";
import Dashboard from "./components/Dashboard";
import './App.css';
// import NotFound from "./components/NotFound";

function App() {
  return (
    <Router>

      <Navbar className = "navbar"/>
      <main className="main-content">
      <Switch>
        <Route exact path="/" component={LandingPage} />
        
        <Route path="/dashboard" component={Dashboard} />
        {/* <Route component={NotFound} /> */}
      </Switch>
      </main>
    </Router>
  );
}

export default App;
