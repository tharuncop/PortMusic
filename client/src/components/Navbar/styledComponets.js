import styled from "styled-components";

export const Nav = styled.nav`
  box-sizing: border-box;
  position: fixed;
  top: 0;
  width: 100%;
  display: flex;
  justify-content: end; /* Logo on left, button on right */
  align-items: center;
  padding: 1.8rem 5%;
  z-index: 1000;
  background: rgba(255, 255, 255, 0.86);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
  border-bottom: 1px solid rgba(237, 242, 247, 0.8);
`;

export const Button = styled.button`
  background: #2563eb;
  color: white;
  border: none;
  border-radius: 8px;
  padding: 12px 28px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  box-shadow: 0 4px 6px rgba(37, 99, 235, 0.2);
  letter-spacing: 0.5px;

  &:hover {
    background: #1d4ed8;
    transform: translateY(-2px);
    box-shadow: 0 6px 12px rgba(37, 99, 235, 0.25);
  }

  &:active {
    transform: translateY(0);
  }
`;
