import React from 'react';
import './Navbar.css'; // Import the CSS file

export default function Navbar() {
return (
    <nav className="navbar">
      <div className="navbar-content">
        <button className="sign-in-button">
          Sign In
        </button>
      </div>
    </nav>
  );
}