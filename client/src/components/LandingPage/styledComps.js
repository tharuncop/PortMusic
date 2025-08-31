import styled from "styled-components";

export const Hero = styled.section`
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  min-height: 100vh;
  padding: 0 2rem;
  padding-top: 80px;
  background: linear-gradient(120deg, #ffffff 0%, #f0f7ff 100%);
  position: relative;
  overflow: hidden;

  &::before {
    content: "";
    position: absolute;
    width: 150%;
    height: 400px;
    background: linear-gradient(
      90deg,
      rgba(37, 99, 235, 0.08) 0%,
      rgba(37, 99, 235, 0.03) 100%
    );
    top: -20%;
    left: -25%;
    border-radius: 50%;
    z-index: 0;
  }
`;

export const Title = styled.h1`
  font-size: 4.5rem;
  font-weight: 800;
  margin-bottom: 1.2rem;
  color: #1e293b;
  position: relative;
  z-index: 2;
  background: linear-gradient(90deg, #2563eb 0%, #3b82f6 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: -1px;

  @media (max-width: 768px) {
    font-size: 3.2rem;
  }

  @media (max-width: 480px) {
    font-size: 2.8rem;
  }
`;

export const Subtitle = styled.h3`
  font-size: 2.2rem;
  font-weight: 600;
  color: #334155;
  margin-bottom: 1.8rem;
  position: relative;
  z-index: 2;
  max-width: 700px;
  line-height: 1.3;

  @media (max-width: 768px) {
    font-size: 1.8rem;
  }

  @media (max-width: 480px) {
    font-size: 1.5rem;
  }
`;

export const Description = styled.p`
  font-size: 1.25rem;
  color: #4a5568;
  max-width: 600px;
  line-height: 1.6;
  margin-bottom: 2.5rem;
  position: relative;
  z-index: 2;

  @media (max-width: 768px) {
    font-size: 1.1rem;
  }
`;

export const CTAButton = styled.button`
  background: linear-gradient(90deg, #2563eb 0%, #3b82f6 100%);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 18px 42px;
  font-size: 1.1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  box-shadow: 0 6px 15px rgba(37, 99, 235, 0.3);
  position: relative;
  z-index: 2;
  letter-spacing: 0.5px;
  overflow: hidden;

  &::after {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, #3b82f6 0%, #60a5fa 100%);
    opacity: 0;
    transition: opacity 0.4s ease;
    z-index: -1;
    border-radius: 8px;
  }

  &:hover {
    transform: translateY(-4px) scale(1.03);
    box-shadow: 0 12px 25px rgba(37, 99, 235, 0.35);
  }

  &:hover::after {
    opacity: 1;
  }

  &:active {
    transform: translateY(1px);
  }

  @media (max-width: 480px) {
    padding: 16px 36px;
    font-size: 1rem;
  }
`;

export const IconsRow = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  flex-wrap: wrap;
  gap: 2.5rem;
  margin-top: 3.5rem;
  position: relative;
  z-index: 2;
  max-width: 900px;
  padding: 0 2rem;

  @media (max-width: 768px) {
    gap: 1.8rem;
    margin-top: 2.5rem;
  }

  @media (max-width: 480px) {
    gap: 1.2rem;
    margin-top: 2rem;
  }
`;

export const Icon = styled.img`
  border-radius: 20%;
  height: 50px;
  width: auto;
  cursor: pointer;
  opacity: 0.85;
  transition: all 0.3s ease;
  filter: grayscale(30%);

  &:hover {
    opacity: 1;
    transform: translateY(-3px) scale(1.05);
    filter: grayscale(0%);
  }

  @media (max-width: 768px) {
    height: 40px;
  }

  @media (max-width: 480px) {
    height: 32px;
  }
`;
