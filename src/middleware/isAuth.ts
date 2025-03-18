import { verify } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";
import AppError from "../errors/AppError";
import authConfig from "../config/auth";

interface TokenPayload {
  id: string;
  username: string;
  profile: string;
  companyId: number;
  iat: number;
  exp: number;
}

const isAuth = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers.authorization;
  //console.log('authHeader: ', authHeader);
  if (!authHeader) {
    throw new AppError("ERR_SESSION_EXPIRED", 401);
  }

  //authHeader:  Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2FybmFtZSI6IkFkbWluIiwicHJvZmlsZSI6ImFkbWluIiwiaWQiOjEsImNvbXBhbnlJZCI6MSwiaWF0IjoxNzQxNzgyODc5LCJleHAiOjE3NDQzNzQ4Nzl9.24k-uM46HEWC1dTLw25neKS1Fn34S_qN1fEzg9UTMWc
  const [, token] = authHeader.split(" ");

  try {
    //console.log('token: ', token);
    //token:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2FybmFtZSI6IkFkbWluIiwicHJvZmlsZSI6ImFkbWluIiwiaWQiOjEsImNvbXBhbnlJZCI6MSwiaWF0IjoxNzQxNzgyODc5LCJleHAiOjE3NDQzNzQ4Nzl9.24k-uM46HEWC1dTLw25neKS1Fn34S_qN1fEzg9UTMWc
    const decoded = verify(token, authConfig.secret);
    //const decoded = verify(authHeader, authConfig.secret);
    //console.log('decoded: ', decoded);
    const { id, profile, companyId } = decoded as TokenPayload;
    //console.log('profile: ', profile);
    
    req.user = {
      id,
      profile,
      companyId
    };
  } catch (err) {
    throw new AppError("Invalid token. We'll try to assign a new one on next request", 403 );
  }

  return next();
};

export default isAuth;
