// src/components/Dashboard/styledComponets.js
import styled from "styled-components";

/* Page wrapper — leaves space for fixed navbar */
export const Page = styled.div`
  padding: 92px 24px 40px; /* top pad to account for fixed navbar */
  max-width: 960px;
  margin: 0 auto;
  box-sizing: border-box;
`;

/* Header section (title + subtitle) */
export const Header = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
`;

/* Title + subtitle styles */
export const Title = styled.h1`
  margin: 0;
  font-size: 1.6rem;
  color: #0f172a;
`;

export const Sub = styled.div`
  margin-top: 6px;
  color: #64748b;
  font-size: 0.95rem;
`;

/* Row for action controls (buttons) */
export const Controls = styled.div`
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  flex-wrap: wrap;
`;

/* Primary CTA button (connect / fetch) */
export const PrimaryButton = styled.button`
  padding: 9px 14px;
  margin-top: 14px;
  border-radius: 8px;
  background: #2563eb;
  color: white;
  border: none;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 6px 12px rgba(37,99,235,0.12);
  transition: transform .12s ease, box-shadow .12s ease;

  &:hover { transform: translateY(-2px); }
  &:active { transform: translateY(0); }
`;

/* Small neutral button for secondary actions */
export const SmallButton = styled.button`
  padding: 8px 12px;
  border-radius: 8px;
  background: #ffffff;
  border: 1px solid rgba(15,23,42,0.06);
  cursor: pointer;
  font-weight: 600;

  &:hover { transform: translateY(-1px); }
`;

/* Playlist list and item */
export const PlaylistList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
`;

export const PlaylistItem = styled.li`
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid rgba(235,238,241,0.9);
  margin-bottom: 8px;
  background: #fff;
  color: #0f172a;
`;
