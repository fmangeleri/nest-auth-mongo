import {
  Controller,
  Get,
  Query,
  Param,
  Post,
  Body,
  Put,
  Delete,
  HttpStatus,
  HttpCode,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';

import { ParseIntPipe } from '../../common/parse-int.pipe';
import { CreateProductDto, UpdateProductDto } from '../dtos/products.dtos';
import { ProductsService } from './../services/products.service';
import { MongoIdPipe } from '../../common/mongoId.pipe';
import { FilterProductsDto } from '../dtos/products.dtos';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { Public } from 'src/auth/decorators/public.decorator';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { Role } from 'src/auth/models/roles.model';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@UseGuards(JwtAuthGuard, RolesGuard)
@ApiTags('products')
@Controller('products')
export class ProductsController {
  constructor(private productsService: ProductsService) {}

  @Roles(Role.CUSTOMER)
  @Get()
  @ApiOperation({ summary: 'List of products' })
  async getProducts(@Query() params: FilterProductsDto) {
    return await this.productsService.findAll(params);
  }

  @Roles(Role.ADMIN)
  @Get(':productId')
  @HttpCode(HttpStatus.ACCEPTED)
  async getOne(@Param('productId', MongoIdPipe) productId: string) {
    return await this.productsService.findOne(productId);
  }

  @Post()
  async create(@Body() payload: CreateProductDto) {
    return await this.productsService.create(payload);
  }

  @Put(':id')
  async update(
    @Param('id', MongoIdPipe) id: string,
    @Body() payload: UpdateProductDto,
  ) {
    return await this.productsService.update(id, payload);
  }

  @Delete(':id')
  async delete(@Param('id', MongoIdPipe) id: string) {
    return await this.productsService.remove(id);
  }
}
