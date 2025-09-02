// src/components/Navbar/styledComponets.js
import styled from "styled-components";

export const Nav = styled.nav`
  box-sizing: border-box;
  position: fixed;
  top: 0;
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.0rem 5%;
  z-index: 1000;
  background: rgba(255, 255, 255, 1);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
  border-bottom: 1px solid rgba(237, 242, 247, 0.8);
`;

/* Primary CTA button (keeps your visual look) */
export const Button = styled.button`
  background: #2563eb;
  color: white;
  border: none;
  border-radius: 8px;
  padding: 10px 20px;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.18s ease;
  box-shadow: 0 4px 6px rgba(37, 99, 235, 0.14);
  letter-spacing: 0.4px;
  min-width: 96px;

  &:hover {
    background: #1d4ed8;
    transform: translateY(-2px);
    box-shadow: 0 6px 12px rgba(37, 99, 235, 0.18);
  }

  &:active {
    transform: translateY(0);
  }
`;

/* settings symbol circle */
export const SettingsButton = styled.button`
  width: 40px;
  height: 40px;
  border-radius: 8px;
  background: #f1f5f9;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(15,23,42,0.04);
  cursor: pointer;
  transition: all 0.12s ease;
  padding: 0;
  box-shadow: 0 2px 6px rgba(2,6,23,0.04);

  &:hover {
    transform: translateY(-2px);
    background: #eef2ff;
  }

  &:active {
    transform: translateY(0);
  }
`;


/* Dropdown container */
export const Dropdown = styled.div`
  position: absolute;
  right: 0;
  top: 52px;
  width: 240px;
  background: #ffffff;
  border-radius: 10px;
  box-shadow: 0 8px 26px rgba(16, 24, 40, 0.08);
  border: 1px solid rgba(227, 231, 235, 0.8);
  padding: 12px;
  z-index: 2000;
`;

/* Row inside dropdown for items */
export const MenuItem = styled.button`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  background: transparent;
  border: none;
  padding: 8px 6px;
  cursor: pointer;
  font-size: 0.95rem;
  text-align: left;
  border-radius: 8px;

  &:hover {
    background: #f8fafc;
  }
`;

/* Profile name block in dropdown */
export const ProfileBlock = styled.div`
  padding: 8px 6px;
  border-bottom: 1px solid rgba(235, 238, 241, 0.9);
  margin-bottom: 8px;
`;

export const StatusBadge = styled.span`
  font-size: 0.75rem;
  padding: 4px 8px;
  border-radius: 999px;
  background: ${(p) => (p.connected ? "#ecfdf5" : "#fff7ed")};
  color: ${(p) => (p.connected ? "#027a48" : "#92400e")};
  border: 1px solid ${(p) => (p.connected ? "#bbf7d0" : "#ffd8a8")};
`;
