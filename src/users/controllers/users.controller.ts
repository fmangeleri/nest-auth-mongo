import {
  Controller,
  Get,
  Param,
  Post,
  Body,
  Put,
  Delete,
} from '@nestjs/common';

import { MongoIdPipe } from 'src/common/mongoId.pipe';
import { UsersService } from '../services/users.service';
import { CreateUserDto, UpdateUserDto } from '../dtos/user.dto';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  // @Get(':id')
  // get(@Param('id', MongoIdPipe) id: string) {
  //   return this.usersService.findOne(id);
  // }

  @Get(':email')
  get(@Param('email') email: string) {
    return this.usersService.findByEmail(email);
  }

  // @Get(':id/orders')
  // getOrders(@Param('id', MongoIdPipe) id: string) {
  //   return this.usersService.getOrderByUser(id);
  // }

  @Post()
  create(@Body() payload: CreateUserDto) {
    return this.usersService.create(payload);
  }

  @Put(':id')
  update(@Param('id', MongoIdPipe) id: string, @Body() payload: UpdateUserDto) {
    return this.usersService.update(id, payload);
  }

  @Delete(':id')
  remove(@Param('id', MongoIdPipe) id: string) {
    return this.usersService.remove(id);
  }
}
